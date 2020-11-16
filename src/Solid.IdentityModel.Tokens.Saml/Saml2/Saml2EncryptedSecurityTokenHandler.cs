﻿using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using Solid.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Solid.IdentityModel.Tokens.Saml2
{
    public class Saml2EncryptedSecurityTokenHandler : Saml2SecurityTokenHandler
    {
        private static readonly string EncryptedAssertion = "EncryptedAssertion";

        protected X509SecurityKey DecryptionKey { get; }

        public Saml2EncryptedSecurityTokenHandler(Saml2Serializer serializer)
            : base()
        {
            Serializer = new ExtendedSaml2Serializer();
        }

        public Saml2EncryptedSecurityTokenHandler()
            : this(new ExtendedSaml2Serializer())
        {
        }

        public Saml2EncryptedSecurityTokenHandler(X509SecurityKey decryptionKey)
            : this()
        {
            DecryptionKey = decryptionKey;
        }

        public override bool CanReadToken(XmlReader reader)
        {
            if (base.CanReadToken(reader)) return true;
            return IsEncryptedAssertion(reader);
        }

        public virtual SecurityToken ReadToken(string securityToken, TokenValidationParameters validationParameters)
        {
            using (var stream = new MemoryStream(new UTF8Encoding(false).GetBytes(securityToken)))
            using (var reader = XmlReader.Create(stream))
                return ReadToken(reader, validationParameters);
        }

        public override SecurityToken ReadToken(XmlReader reader, TokenValidationParameters validationParameters)
            => ReadSaml2Token(reader, validationParameters);

        public override Saml2SecurityToken ReadSaml2Token(XmlReader reader)
        {
            if (DecryptionKey != null)
                return ReadSaml2Token(reader, CreateDefaultTokenValidationParameters());
            if(IsEncryptedAssertion(reader))
                throw new InvalidOperationException($"Unable to read SAML2 encrypted assertion without the decryption key.");
            return base.ReadSaml2Token(reader);
        }

        public virtual Saml2SecurityToken ReadSaml2Token(XmlReader reader, TokenValidationParameters validationParameters)
        {
            if (IsEncryptedAssertion(reader))
            {
                reader.Read();
                using(var sub = reader.ReadSubtree())
                {
                    sub.MoveToContent();
                    using (var decrypting = new DecryptingXmlDictionaryReader(sub, validationParameters))
                    {
                        var token = base.ReadSaml2Token(decrypting);
                        return new Saml2EncryptedSecurityToken(token, decrypting.EncryptedData);
                    }
                }
            }
            return base.ReadSaml2Token(reader);
        }

        public override ClaimsPrincipal ValidateToken(XmlReader reader, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            var inner = null as XmlReader;
            var token = null as SecurityToken;
            if (IsEncryptedAssertion(reader))
            {
                reader.Read();
                using (var sub = reader.ReadSubtree())
                {
                    sub.MoveToContent();
                    using (var decrypting = new DecryptingXmlDictionaryReader(sub, validationParameters))
                    {
                        var saml2 = base.ReadSaml2Token(decrypting);
                        token = new Saml2EncryptedSecurityToken(saml2, decrypting.EncryptedData);

                        inner = XmlReader.Create(new MemoryStream(decrypting.PlainText), reader.Settings);
                        reader = inner;
                    }
                }
            }

            var user = base.ValidateToken(reader, validationParameters, out var t);
            validatedToken = token ?? t;
            inner?.Dispose();
            return user;
        }

        public override ClaimsPrincipal ValidateToken(string token, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            var utf8 = new UTF8Encoding(false);
            using (var stream = new MemoryStream(utf8.GetBytes(token)))
            using (var reader = XmlReader.Create(stream))
            {
                reader.MoveToContent();
                return ValidateToken(reader, validationParameters, out validatedToken);
            }
        }

        public override SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            var token = base.CreateToken(tokenDescriptor) as Saml2SecurityToken;
            if (tokenDescriptor?.EncryptingCredentials == null) return token;

            return new Saml2EncryptedSecurityToken(token, tokenDescriptor.EncryptingCredentials);
        }

        public override SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor, AuthenticationInformation authenticationInformation)
        {
            var token = base.CreateToken(tokenDescriptor, authenticationInformation) as Saml2SecurityToken;
            if (tokenDescriptor?.EncryptingCredentials == null) return token;

            return new Saml2EncryptedSecurityToken(token, tokenDescriptor.EncryptingCredentials);
        }

        public override string WriteToken(SecurityToken securityToken)
        {
            if (securityToken is Saml2EncryptedSecurityToken encrypted)
                return WriteEncryptedSecurityToken(encrypted);
            return base.WriteToken(securityToken);
        }

        public override void WriteToken(XmlWriter writer, SecurityToken securityToken)
        {
            if (securityToken is Saml2EncryptedSecurityToken encrypted)
                WriteEncryptedSecurityToken(writer, encrypted);
            else
                base.WriteToken(writer, securityToken);
        }

        public virtual void WriteEncryptedSecurityToken(XmlWriter writer, Saml2EncryptedSecurityToken securityToken)
        {
            if (writer == null) throw new ArgumentNullException(nameof(writer));
            if (securityToken == null) throw new ArgumentNullException(nameof(securityToken));

            using (var encrypting = new EncryptingXmlDictionaryWriter(writer, securityToken.EncryptingCredentials, (_, localName, ns) => IsSaml2Assertion(localName, ns)))
            {
                encrypting.WriteStartElement(Saml2Constants.Prefix, EncryptedAssertion, Saml2Constants.Namespace);
                base.WriteToken(encrypting, securityToken);
                encrypting.WriteEndElement();
            }
        }

        public virtual string WriteEncryptedSecurityToken(Saml2EncryptedSecurityToken securityToken)
        {
            using (var stream = new MemoryStream())
            {
                using (var writer = XmlWriter.Create(stream, XmlSettings.DefaultWriterSettings))
                    WriteEncryptedSecurityToken(writer, securityToken);
                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }
        protected override Saml2Subject CreateSubject(SecurityTokenDescriptor tokenDescriptor)
        {
            var subject = base.CreateSubject(tokenDescriptor);

            if (subject.NameId.Format == null)
                subject.NameId.Format = Saml2Constants.NameIdentifierFormats.Unspecified;

            //if (tokenDescriptor is RequestedSecurityTokenDescriptor extended && extended.ProofKey != null)
            //{
               
            //    if (HolderOfKeyHack.ShouldAddHolderOfKeysSubjectConfirmation(extended))
            //        HolderOfKeyHack.AddHolderOfKeysSubjectConfirmation(subject, extended);
            //}

            return subject;
        }

        private bool IsEncryptedAssertion(XmlReader reader) => reader.IsStartElement(EncryptedAssertion, Saml2Constants.Namespace);
        private bool IsSaml2Assertion(string localName, string ns) => localName == Saml2Constants.Elements.Assertion && ns == Saml2Constants.Namespace;

        private TokenValidationParameters CreateDefaultTokenValidationParameters()
            => new TokenValidationParameters
            {
                TokenDecryptionKey = DecryptionKey
            };
    }
}

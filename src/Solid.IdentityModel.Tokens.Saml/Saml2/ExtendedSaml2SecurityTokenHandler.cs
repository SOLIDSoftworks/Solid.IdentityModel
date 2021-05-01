using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using Solid.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Xml;

namespace Solid.IdentityModel.Tokens.Saml2
{
    public class ExtendedSaml2SecurityTokenHandler : Saml2SecurityTokenHandler, IDisposable
    {
        protected Encoding Utf8 { get; } = new UTF8Encoding(false);

        private IDisposable _optionsChangeToken;
        protected Saml2Options Options { get; private set; }

        public ExtendedSaml2SecurityTokenHandler(ExtendedSaml2Serializer serializer, Saml2Options options)
            : base()
        {
            Serializer = serializer;
            Options = options;
        }

        public ExtendedSaml2SecurityTokenHandler()
            : this(new ExtendedSaml2Serializer(), new Saml2Options())
        {
        }

        public ExtendedSaml2SecurityTokenHandler(IOptionsMonitor<Saml2Options> monitor)
        {
            _optionsChangeToken = monitor.OnChange((options, _) => Options = options);
        }

        // protected virtual SecurityKey GetProofKey(Saml2SubjectConfirmation holderOfKey, TokenValidationParameters validationParameters)
        // {
        //     var info = holderOfKey.SubjectConfirmationData.KeyInfos.SingleOrDefault();

        //     if (info == null) return null;

        //     if (info is BinarySecretKeyInfo binary)
        //         return new SymmetricSecurityKey(binary.Key);

        //     if(info is EncryptedKeyInfo encrypted)
        //     {
        //         foreach(var key in validationParameters.key)
        //     }

        //     return null;
        // }

        public void Dispose() => _optionsChangeToken?.Dispose();

        protected override Saml2Subject CreateSubject(SecurityTokenDescriptor tokenDescriptor)
        {
            var subject = base.CreateSubject(tokenDescriptor);

            if (subject.NameId != null && subject.NameId.Format == null)
                subject.NameId.Format = Saml2Constants.NameIdentifierFormats.Unspecified;

            if (tokenDescriptor is RequestedSecurityTokenDescriptor requestedTokenDescriptor)
            {
                var keyInfo = CreateProofKeyInfo(requestedTokenDescriptor);
                if (keyInfo != null)
                {
                    var data = new Saml2SubjectConfirmationData
                    {
                    };
                    data.KeyInfos.Add(keyInfo);
                    var holderOfKey = new Saml2SubjectConfirmation(Saml2Constants.ConfirmationMethods.HolderOfKey, data);

                    var bearer = subject.SubjectConfirmations.FirstOrDefault(c => c.Method == Saml2Constants.ConfirmationMethods.Bearer);
                    if (bearer != null)
                        subject.SubjectConfirmations.Remove(bearer);

                    subject.SubjectConfirmations.Add(holderOfKey);
                }
            }

            return subject;
        }

        protected virtual KeyInfo CreateProofKeyInfo(RequestedSecurityTokenDescriptor tokenDescriptor)
        {
            if (tokenDescriptor.ProofKey == null) return null;

            if (tokenDescriptor.ProofKey is SymmetricSecurityKey symmetric)
            {
                var credentials = tokenDescriptor.ProofKeyEncryptingCredentials;
                if (credentials == null)
                    return new BinarySecretKeyInfo { Key = symmetric.Key };

                var crypto = credentials.CryptoProviderFactory ?? credentials.Key.CryptoProviderFactory ?? CryptoProviderFactory.Default;
                var keyWrap = null as KeyWrapProvider;
                try
                {
                    keyWrap = crypto.CreateKeyWrapProvider(credentials.Key, credentials.Alg);
                    var wrapped = keyWrap.WrapKey(symmetric.Key);
                    var cipherValue = wrapped;
                    return new EncryptedKeyInfo
                    {
                        CipherValue = cipherValue,
                        EncryptionMethod = credentials.Alg,
                        KeyInfo = CreateKeyInfo(credentials.Key)
                    };
                }
                finally
                {
                    crypto?.ReleaseKeyWrapProvider(keyWrap);
                }
            }
            else if (tokenDescriptor.ProofKey is AsymmetricSecurityKey)
            {
                throw new NotSupportedException($"Asymmetric proof keys not supproted for now.");
            }
            else
            {
                throw new NotSupportedException($"Key type '{tokenDescriptor.ProofKey.GetType().Name}' not supported.");
            }
        }

        protected virtual KeyInfo CreateKeyInfo(SecurityKey key)
        {
            if (key is X509SecurityKey x509)
            {
                if (Options.UseSecurityTokenReference)
                {
                    return new SecurityTokenReferenceKeyInfo
                    {
                        KeyIdValueType = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1",
                        KeyId = x509.X5t
                    };
                }

                return new KeyInfo
                {
                    X509Data =
                    {
                        new X509Data(x509.Certificate)
                    }
                };
            }
            else if (key is RsaSecurityKey rsa)
            {
                var id = Options.GenerateId(rsa);
                return new KeyInfo { KeyName = id };
            }

            throw new NotSupportedException($"Key type '{key.GetType().Name}' not supported.");
        }

        protected virtual TokenValidationParameters CreateDefaultTokenValidationParameters()
        {
            if (Options.DefaultDecryptionKey == null) return null;
            return new TokenValidationParameters
            {
                TokenDecryptionKey = Options.DefaultDecryptionKey
            };
        }
    }
}

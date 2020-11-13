using Microsoft.IdentityModel.Tokens;
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

        //public XmlEncSerializer EncryptionSerializer { get; set; }

        public Saml2EncryptedSecurityTokenHandler()
            : base()
        {
            //EncryptionSerializer = XmlEncSerializer.Default;
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
            return user;



            //    if (!TryReadSaml2EncryptedAssertion(reader, out var encrypted))
            //        throw new XmlException("Unable to reader encrypted assertion.");

            //    var plainText = null as byte[];
            //    var keys = ResolveDecryptionKeys(encrypted, validationParameters);
            //    foreach (var key in keys)
            //    {
            //        try
            //        {
            //            plainText = Decrypt(key, encrypted.EncryptedData);
            //        }
            //        catch (Exception ex)
            //        {
            //        }
            //    }
            //    if (plainText == null)
            //        throw new SecurityTokenValidationException("Could not validate encrypted assertion.");

            //    using (var stream = new MemoryStream(plainText))
            //    using (var inner = XmlReader.Create(stream))
            //    {
            //        user = base.ValidateToken(inner, validationParameters, out var saml2);
            //        validatedToken = new Saml2EncryptedSecurityToken(saml2 as Saml2SecurityToken, encrypted);
            //    }
            //}
            //else
            //{
            //    user = base.ValidateToken(reader, validationParameters, out var saml2);
            //    validatedToken = new Saml2EncryptedSecurityToken(saml2 as Saml2SecurityToken, null);
            //}
            //return user;
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
            //var credentials = tokenDescriptor.EncryptingCredentials;
            //using (var stream = new MemoryStream())
            //{
            //    using (var writer = XmlWriter.Create(stream, XmlSettings.DefaultWriterSettings))
            //        WriteToken(writer, token);

            //    var data = Encrypt(credentials, stream.ToArray());
            //    var assertion = new Saml2EncryptedAssertion { EncryptedData = data };
            //    return new Saml2EncryptedSecurityToken(token, assertion);
            //}
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

            using (var encrypting = new EncryptingXmlDictionaryWriter(writer, securityToken.EncryptingCredentials))
            {
                writer.WriteStartElement(Saml2Constants.Prefix, "EncryptedAssertion", Saml2Constants.Namespace);
                base.WriteToken(encrypting, securityToken);
                writer.WriteEndElement();
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

        //protected bool TryReadEncryptedData(XmlReader reader, out EncryptedData encryptedData)
        //{
        //    if (!IsEncryptedAssertion(reader))
        //        return False(out encryptedData);

        //    if (!reader.Read() || !reader.IsStartElement("EncryptedData", EncryptedXml.XmlEncNamespaceUrl))
        //        throw new SecurityTokenDecryptionFailedException("EncryptedAssertion did not contain an EncryptedData element.");

        //    var xml = reader.ReadOuterXml();
        //    var document = new XmlDocument();
        //    document.LoadXml(xml);

        //    var data = new EncryptedData();
        //    data.LoadXml(document.DocumentElement);

        //    encryptedData = data;

        //    return true;
        //}

        //protected virtual Saml2Assertion DecryptEncryptedAssertion(Saml2EncryptedAssertion encryptedAssertion, TokenValidationParameters validationParameters)
        //{
        //    var keys = ResolveDecryptionKeys(encryptedAssertion, validationParameters);

        //    foreach(var key in keys)
        //    {
        //        if (TryDecryptAssertion(encryptedAssertion, key, out var assertion))
        //            return assertion;
        //    }
        //    throw new CryptographicException("Unable to decrypt encrypted assertion.");
        //}

        //private bool TryDecryptAssertion(Saml2EncryptedAssertion encryptedAssertion, SecurityKey key, out Saml2Assertion assertion)
        //{
        //    var plainText = Decrypt(key, encryptedAssertion.EncryptedData); 
        //    using (var stream = new MemoryStream(plainText))
        //    using (var reader = XmlReader.Create(stream))
        //    {
        //        reader.MoveToContent();
        //        assertion = Serializer.ReadAssertion(reader);
        //        return assertion != null;
        //    }
        //}

        //private IEnumerable<SecurityKey> ResolveDecryptionKeys(EncryptedData encryptedData, TokenValidationParameters validationParameters)
        //{
        //    var kid = null as string;
        //    if (encryptedAssertion.EncryptedData.KeyInfo.EncryptedKey != null)
        //    {
        //        var k = encryptedAssertion.EncryptedData.KeyInfo.EncryptedKey;
        //        kid = k.KeyInfo?.SecurityTokenReference.KeyIdentifier.Value;
        //    }
        //    var keys = ResolveDecryptionKeys(validationParameters, kid);
        //    return keys;
        //}

        private IEnumerable<SecurityKey> ResolveDecryptionKeys(TokenValidationParameters validationParameters, string kid)
        {
            if (DecryptionKey != null) yield return DecryptionKey;
            foreach (var key in validationParameters.ResolveDecryptionKeys())
                yield return key;
        }

        private bool IsEncryptedAssertion(XmlReader reader) => reader.IsStartElement(EncryptedAssertion, Saml2Constants.Namespace);

        private TokenValidationParameters CreateDefaultTokenValidationParameters()
            => new TokenValidationParameters
            {
            };

        private bool False<T>(out T obj)
        {
            obj = default;
            return false;
        }

        //private EncryptedData Encrypt(EncryptingCredentials credentials, byte[] plainText)
        //{
        //    var data = null as EncryptedData;

        //    var key = credentials.Key;
        //    var encryptingAlgorithm = credentials.Enc;
        //    var keyWrapAlgorithm = credentials.Alg;

        //    if (key is SymmetricSecurityKey)
        //    {
        //        data = Encrypt<EncryptedData>(key, encryptingAlgorithm, plainText);
        //    }
        //    else if(keyWrapAlgorithm != null)
        //    {
        //        var bytes = new byte[GetKeyBytesLength(encryptingAlgorithm)];
        //        var random = RandomNumberGenerator.Create();
        //        random.GetNonZeroBytes(bytes);
        //        var symmetric = new SymmetricSecurityKey(bytes);

        //        data = Encrypt<EncryptedData>(symmetric, encryptingAlgorithm, plainText);
        //        data.KeyInfo = new ExtendedKeyInfo
        //        {
        //            EncryptedKey = Encrypt<EncryptedKey>(key, keyWrapAlgorithm, bytes)
        //        };
        //    }

        //    return data;
        //}

        //private int GetKeyBytesLength(string encryptingAlgorithm)
        //{
        //    if (encryptingAlgorithm == SecurityAlgorithms.Aes128Encryption)
        //        return 16;
        //    if (encryptingAlgorithm == SecurityAlgorithms.Aes192Encryption)
        //        return 24;
        //    if (encryptingAlgorithm == SecurityAlgorithms.Aes256Encryption)
        //        return 32;

        //    throw new NotSupportedException($"Algortihm '{encryptingAlgorithm}' not supported.");
        //}

        //private T Encrypt<T>(SecurityKey key, string algorithm, byte[] plainText)
        //    where T : EncryptedType, new()
        //{
        //    var crypto = key.CryptoProviderFactory ?? CryptoProviderFactory.Default;

        //    if (key is SymmetricSecurityKey symmetric)
        //    {
        //        if (crypto.IsSupportedAlgorithm(algorithm))
        //        {
        //            var provider = crypto.CreateAuthenticatedEncryptionProvider(key, algorithm);
        //            var result = provider.Encrypt(plainText, null);
        //            return new T
        //            {
        //                EncryptionMethod = new EncryptionMethod(algorithm),
        //                CipherData = new CipherData { CipherValue = result.Ciphertext }
        //            };
        //        }
        //        else if (
        //           algorithm == SecurityAlgorithms.Aes128Encryption ||
        //           algorithm == SecurityAlgorithms.Aes192Encryption ||
        //           algorithm == SecurityAlgorithms.Aes256Encryption)
        //        {
        //            using (var aes = Aes.Create())
        //            {
        //                aes.Key = symmetric.Key;
        //                aes.KeySize = symmetric.KeySize;
        //                aes.Padding = PaddingMode.ISO10126;
        //                aes.GenerateIV();
        //                using (var encryptor = aes.CreateEncryptor())
        //                {
        //                    var cipherText = encryptor.TransformFinalBlock(plainText, 0, plainText.Length);
        //                    return new T
        //                    {
        //                        EncryptionMethod = new EncryptionMethod(algorithm),
        //                        CipherData = new CipherData { CipherValue = aes.IV.Concat(cipherText).ToArray() }
        //                    };
        //                }
        //            }
        //        }
        //    }
        //    else
        //    {
        //        if (crypto.IsSupportedAlgorithm(algorithm, key))
        //        {
        //            var keyWrap = crypto.CreateKeyWrapProvider(key, algorithm);
        //            var keyInfo = CreateKeyInfo(key, out var digest);
        //            return new T
        //            {
        //                EncryptionMethod = new EncryptionMethod(algorithm) { DigestMethod = new DigestMethod(digest) },
        //                KeyInfo = keyInfo,
        //                CipherData = new CipherData { CipherValue = keyWrap.WrapKey(plainText) }
        //            };
        //        }
        //    }

        //    throw new NotSupportedException($"Algortihm '{algorithm}' not supported.");
        //}

        //private ExtendedKeyInfo CreateKeyInfo(SecurityKey key, out string digestMethod)
        //{
        //    if (key is X509SecurityKey x509)
        //    {
        //        var crypto = key.CryptoProviderFactory ?? CryptoProviderFactory.Default;
        //        digestMethod = "http://www.w3.org/2000/09/xmldsig#sha1";

        //        var hash = crypto.CreateHashAlgorithm(digestMethod);

        //        var info = new ExtendedKeyInfo
        //        {
        //            SecurityTokenReference = new SecurityTokenReference
        //            {
        //                KeyIdentifier = new KeyIdentifier
        //                {
        //                    ValueType = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1",
        //                    Value = Convert.ToBase64String(hash.ComputeHash(x509.Certificate.GetCertHash()))
        //                }
        //            }
        //        };

        //        return info;
        //    }
        //    digestMethod = null;
        //    return null;
        //}

        //private byte[] Decrypt(SecurityKey key, EncryptedType data)
        //{
        //    var crypto = key.CryptoProviderFactory ?? CryptoProviderFactory.Default;
        //    var algorithm = data.EncryptionMethod.Algorithm;
        //    var cipherText = data.CipherData.CipherValue;

        //    if (data.KeyInfo.EncryptedKey == null)
        //    {
        //        throw new Exception("Not handling this yet");
        //    }
        //    else
        //    {
        //        var encryptedKey = data.KeyInfo.EncryptedKey;
        //        var keyWrapAlgorithm = encryptedKey.EncryptionMethod.Algorithm;
        //        var keyWrap = crypto.CreateKeyWrapProviderForUnwrap(key, keyWrapAlgorithm);
        //        var bytes = keyWrap.UnwrapKey(encryptedKey.CipherData.CipherValue);
        //        var symmetric = new SymmetricSecurityKey(bytes);

        //        if (crypto.IsSupportedAlgorithm(algorithm, key))
        //        {
        //            var provider = crypto.CreateAuthenticatedEncryptionProvider(key, algorithm);
        //            return provider.Decrypt(cipherText, null, null, null);
        //        }
        //        else if (
        //            algorithm == SecurityAlgorithms.Aes128Encryption ||
        //            algorithm == SecurityAlgorithms.Aes192Encryption ||
        //            algorithm == SecurityAlgorithms.Aes256Encryption)
        //        {
        //            var length = GetKeyBytesLength(algorithm);
        //            var iv = cipherText.Take(length).ToArray();
        //            var encrypted = cipherText.Skip(length).ToArray();
        //            using (var aes = Aes.Create())
        //            {
        //                aes.Mode = CipherMode.CBC;
        //                aes.Key = symmetric.Key;
        //                aes.IV = iv;
        //                aes.Padding = PaddingMode.ISO10126;
        //                using (var decryptor = aes.CreateDecryptor())
        //                    return decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
        //            }
        //        }
        //    }

        //    throw new NotSupportedException($"Algortihm '{algorithm}' not supported.");
        //}
    }
}

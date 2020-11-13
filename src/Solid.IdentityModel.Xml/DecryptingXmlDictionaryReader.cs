using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using KeyInfo = System.Security.Cryptography.Xml.KeyInfo;

namespace Solid.IdentityModel.Xml
{
    public class DecryptingXmlDictionaryReader : DelegatingXmlDictionaryReader
    {
        private XmlDictionaryReader _inner;
        private TokenValidationParameters _tokenValidationParameters;

        public DecryptingXmlDictionaryReader(XmlReader reader, TokenValidationParameters tokenValidationParameters)
        {
            _inner = CreateDictionaryReader(reader);
            _tokenValidationParameters = tokenValidationParameters;
            InnerReader = _inner;
            ProcessCurrentElement();
        }

        public EncryptedData EncryptedData { get; private set; }
        public byte[] PlainText { get; private set; }

        public override bool Read()
        {
            base.Read();
            ProcessCurrentElement();
            return !InnerReader.EOF;
        }

        private void ProcessCurrentElement()
        {
            if(!ReferenceEquals(InnerReader, _inner)) // already decrypting
            {
                if (InnerReader.EOF)
                {
                    InnerReader.Dispose();
                    InnerReader = _inner;
                }
            }
            else if(TryReadEncryptedData(out var data))
            {
                EncryptedData = data;
                if (!TryDecrypt(data, out var plainText))
                    throw new CryptographicException("Unable to decrypt encrypted XML.");
                PlainText = plainText;
                var stream = new MemoryStream(plainText);
                InnerReader = CreateDictionaryReader(Create(stream, InnerReader.Settings));
                InnerReader.MoveToContent();
            }
        }

        private bool TryReadEncryptedData(out EncryptedData encryptedData)
        {
            if(!InnerReader.IsStartElement("EncryptedData", EncryptedXml.XmlEncNamespaceUrl))
                return Out.False(out encryptedData);

            var xml = InnerReader.ReadOuterXml();
            var document = new XmlDocument();
            document.LoadXml(xml);
            var data = new EncryptedData();
            data.LoadXml(document.DocumentElement);

            encryptedData = data;
            return true;
        }

        private bool TryDecrypt(EncryptedType encryptedType, out byte[] plainText)
        {
            var xml = new EncryptedXml();
            var keys = GetSecurityKeys(encryptedType);
            var algorithm = encryptedType.EncryptionMethod.KeyAlgorithm;
            foreach(var key in keys)
            {
                try
                {
                    if(encryptedType is EncryptedData encryptedData)
                    {
                        if (!(key is SymmetricSecurityKey symmetricKey)) continue;
                        using (var symmetric = SymmetricAlgorithmProvider.GetSymmetricAlgorithm(algorithm, symmetricKey))
                        {
                            symmetric.IV = xml.GetDecryptionIV(encryptedData, algorithm);
                            var pt = xml.DecryptData(encryptedData, symmetric);
                            plainText = pt;
                            return true;
                        }
                    }

                    if(encryptedType is EncryptedKey encryptedKey)
                    {
                        var pt = null as byte[];
                        if (key is X509SecurityKey x509 && TryDecryptKey(encryptedKey, x509.Certificate, out pt))
                        {
                            plainText = pt;
                            return true;
                        }
                        else if (key is RsaSecurityKey rsa && TryDecryptKey(encryptedKey, rsa.Rsa, out pt))
                        {
                            plainText = pt;
                            return true;
                        }
                        else if(key is SymmetricSecurityKey symmetricKey)
                        {
                            using (var symmetric = SymmetricAlgorithmProvider.GetSymmetricAlgorithm(algorithm, symmetricKey))
                            {
                                pt = EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, symmetric);
                                plainText = pt;
                                return true;
                            }
                        }
                    }
                }
                catch(Exception ex)
                {

                }
            }
            return Out.False(out plainText);
        }

        private bool TryDecryptKey(EncryptedKey encryptedKey, RSA rsa, out byte[] plainText)
        {
            var cipherText = encryptedKey.CipherData.CipherValue;
            try
            {
                var pt = EncryptedXml.DecryptKey(cipherText, rsa, true);
                plainText = pt;
                return true;
            }
            catch { }
            try
            {
                var pt = EncryptedXml.DecryptKey(cipherText, rsa, false);
                plainText = pt;
                return true;
            }
            catch { }
            return Out.False(out plainText);
        }

        private bool TryDecryptKey(EncryptedKey encryptedKey, X509Certificate2 certificate, out byte[] plainText)
        {
            if (!certificate.HasPrivateKey) 
                return Out.False(out plainText);

            using (var rsa = certificate.GetRSAPrivateKey())
                return TryDecryptKey(encryptedKey, rsa, out plainText);
        }

        private IEnumerable<SecurityKey> GetSecurityKeys(EncryptedType encryptedType)
        {
            var keys = new List<SecurityKey>();
            foreach (var clause in encryptedType.KeyInfo.Cast<KeyInfoClause>())
            {
                if (clause is KeyInfoEncryptedKey encryptedKey && TryDecrypt(encryptedKey.EncryptedKey, out var symmetricKey))
                    keys.Add(new SymmetricSecurityKey(symmetricKey));
                if (clause is KeyInfoName name)
                    keys.AddRange(_tokenValidationParameters.ResolveDecryptionKeys(kid: name.Value));
                if (clause is KeyInfoX509Data x509)
                    keys.AddRange(x509.Certificates.Cast<X509Certificate2>().Select(cert => new X509SecurityKey(cert)));
                if (clause is KeyInfoNode node)
                {
                    if(node.Value.LocalName == "SecurityTokenReference")
                        keys.AddRange(_tokenValidationParameters.ResolveDecryptionKeys(kid: node.Value.InnerText));
                }
            }
            return keys;
        }

        //private bool TryDecrypt(EncryptedData encryptedData, out byte[] plainText)
        //{
        //    var keys = GetDecryptionKeys(encryptedData.KeyInfo);
        //    var xml = new EncryptedXml();
        //    xml.Mode = SymmetricAlgorithmProvider.GetCipherMode(encryptedData.EncryptionMethod.KeyAlgorithm);
        //    foreach(var key in keys)
        //    {
        //        try
        //        {
        //            using (var symmetric = SymmetricAlgorithmProvider.GetSymmetricAlgorithm(encryptedData.EncryptionMethod.KeyAlgorithm, key))
        //            {
        //                var pt = xml.DecryptData(encryptedData, symmetric);
        //                plainText = pt;
        //                return true;
        //            }
        //        }
        //        catch(Exception ex)
        //        {

        //        }
        //    }
        //    return Out.False(out plainText);
        //}

        //private bool TryDecrypt(string algorithm, byte[] cipherText, KeyInfo keyInfo, out byte[] plainText)
        //{
        //    var keys = new List<SecurityKey>();
        //    foreach (var clause in keyInfo.Cast<KeyInfoClause>())
        //    {
        //        if (clause is KeyInfoEncryptedKey encryptedKey && TryDecrypt(encryptedKey.EncryptedKey, out var symmetricKey))
        //            keys.Add(new SymmetricSecurityKey(symmetricKey));
        //        if (clause is KeyInfoName name)
        //            keys.AddRange(_tokenValidationParameters.ResolveDecryptionKeys(kid: name.Value));
        //        if (clause is KeyInfoX509Data x509)
        //            keys.AddRange(x509.Certificates.Cast<X509Certificate2>().Select(cert => new X509SecurityKey(cert)));
        //    }
        //    return TryDecrypt(algorithm, cipherText, keys, out plainText);
        //}

        //private bool TryDecrypt(string algorithm, byte[] cipherText, IEnumerable<SecurityKey> keys, out byte[] plainText)
        //{
        //    foreach(var key in keys)
        //    {
        //        if(key is SymmetricSecurityKey symmetricKey)
        //        {
        //            using (var symmetric = SymmetricAlgorithmProvider.GetSymmetricAlgorithm(algorithm, symmetricKey))
        //            using(var decryptor = symmetric.CreateDecryptor())
        //            {
        //                try
        //                {
        //                    var encryptedXml = new EncryptedXml();
        //                   encryptedXml.DecryptData()
        //                }
        //                catch (Exception ex) { }
        //            }
        //        }
        //        else
        //        {
        //            var crypto = key.CryptoProviderFactory ?? CryptoProviderFactory.Default;
        //            if (!crypto.IsSupportedAlgorithm(algorithm) && !crypto.IsSupportedAlgorithm(algorithm, key)) continue;
        //        }
        //    }

        //    return Out.False(out plainText);
        //}
    }
}

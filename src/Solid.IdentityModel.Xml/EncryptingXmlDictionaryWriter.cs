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
    public delegate bool StartEncryptionDelegate(string prefix, string localName, string ns);
    public class EncryptingXmlDictionaryWriter : DelegatingXmlDictionaryWriter
    {
        private static readonly StartEncryptionDelegate _yes = (_, __, ___) => true;

        private XmlDictionaryWriter _writer;
        private EncryptingCredentials _credentials;
        private StartEncryptionDelegate _startEncryption;
        private int _elements;
        private MemoryStream _stream;

        protected CryptoProviderFactory Crypto => _credentials.CryptoProviderFactory ?? _credentials.Key.CryptoProviderFactory ?? CryptoProviderFactory.Default;

        public bool UseRsaOaep
        {
            get
            {
                var key = _credentials.Key;
                if (!(key is X509SecurityKey) && !(key is RsaSecurityKey)) 
                    throw new InvalidOperationException("Cannot key wrap with RSA without RSA key.");

                return 
                    _credentials.Alg == SecurityAlgorithms.RsaOaepKeyWrap || 
                    _credentials.Alg == "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
            }
        }

        /// <summary>
        /// Encrypts an XML element while writing.
        /// </summary>
        /// <param name="writer">The original <see cref="XmlWriter"/>.</param>
        /// <param name="credentials">The <see cref="EncryptingCredentials"/> used to encrypt the XML element.</param>
        public EncryptingXmlDictionaryWriter(XmlWriter writer, EncryptingCredentials credentials) : this(writer, credentials, _yes) { }

        /// <summary>
        /// Encrypts an XML element while writing.
        /// </summary>
        /// <param name="writer">The original <see cref="XmlDictionaryWriter"/>.</param>
        /// <param name="credentials">The <see cref="EncryptingCredentials"/> used to encrypt the XML element.</param>
        public EncryptingXmlDictionaryWriter(XmlDictionaryWriter writer, EncryptingCredentials credentials) : this(writer, credentials, _yes) { }
            

        /// <summary>
        /// Encrypts an XML element while writing.
        /// </summary>
        /// <param name="writer">The original <see cref="XmlWriter"/>.</param>
        /// <param name="credentials">The <see cref="EncryptingCredentials"/> used to encrypt the XML element.</param>
        /// <param name="startEncryption">A delegate to decide on what element encryption should start.</param>
        public EncryptingXmlDictionaryWriter(XmlWriter writer, EncryptingCredentials credentials, StartEncryptionDelegate startEncryption)
            : this(CreateDictionaryWriter(writer), credentials, startEncryption)
        {
        }

        /// <summary>
        /// Encrypts an XML element while writing.
        /// </summary>
        /// <param name="writer">The original <see cref="XmlDictionaryWriter"/>.</param>
        /// <param name="credentials">The <see cref="EncryptingCredentials"/> used to encrypt the XML element.</param>
        /// <param name="startEncryption">A delegate to decide on what element encryption should start.</param>
        public EncryptingXmlDictionaryWriter(XmlDictionaryWriter writer, EncryptingCredentials credentials, StartEncryptionDelegate startEncryption)
        {
            _writer = writer;
            _credentials = credentials;
            _startEncryption = startEncryption;

            _elements = 0;
            _stream = new MemoryStream();
            InnerWriter = CreateDictionaryWriter(Create(_stream, _writer.Settings));
        }

        public override void WriteStartElement(string prefix, string localName, string ns)
        {
            if(_elements > 0 || _startEncryption(prefix, localName, ns))
                _elements++;
            base.WriteStartElement(prefix, localName, ns);
        }

        public override void WriteFullEndElement()
        {
            base.WriteFullEndElement();
            if (--_elements == 0)
            {
                base.Flush();
                Encrypt();
            }
        }

        public override void WriteEndElement()
        {
            base.WriteEndElement();
            if (--_elements == 0)
            {
                base.Flush();
                Encrypt();
            }
        }

        private void Encrypt()
        {
            _stream.Position = 0;
            var algorithm = _credentials.Enc;

            var document = new XmlDocument();
            document.Load(_stream);

            using (var symmetric = GetSymmetricAlgorithm(algorithm))
            {
                var xml = new EncryptedXml();
                xml.Mode = SymmetricAlgorithmProvider.GetCipherMode(algorithm);
                var cipherText = xml.EncryptData(document.DocumentElement, symmetric, false);

                var keyInfo = new KeyInfo();
                var data = new EncryptedData
                {
                    Type = EncryptedXml.XmlEncElementUrl,
                    EncryptionMethod = new EncryptionMethod(algorithm),
                    CipherData = new CipherData { CipherValue = cipherText }
                };

                if (_credentials.Key is RsaSecurityKey rsa)
                    throw new NotSupportedException("RSA security not supported for now.");
                else if (_credentials.Key is X509SecurityKey x509)
                    keyInfo.AddClause(CreateEncryptedKeyClause(symmetric.Key, x509.Certificate, document));
                else if (!string.IsNullOrEmpty(_credentials.Key.KeyId))
                    keyInfo.AddClause(new KeyInfoName(_credentials.Key.KeyId));

                if (keyInfo.Cast<KeyInfoClause>().Any())
                    data.KeyInfo = keyInfo;

                var element = data.GetXml();
                _writer.WriteNode(element.CreateNavigator(), true);
            }
        }

        private KeyInfoClause CreateEncryptedKeyClause(byte[] key, X509Certificate2 certificate, XmlDocument document)
        {
            var keyInfo = new KeyInfo();
            keyInfo.AddClause(CreateKeyInfoClause(certificate, document));
            using (var rsa = certificate.GetRSAPublicKey())
            {
                var cipherValue = EncryptedXml.EncryptKey(key, rsa, UseRsaOaep);
                var encryptedKey = new EncryptedKey
                {
                    CipherData = new CipherData { CipherValue = cipherValue },
                    EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSAOAEPUrl),
                    KeyInfo = keyInfo
                };

                return new KeyInfoEncryptedKey { EncryptedKey = encryptedKey };
            }
        }

        private KeyInfoClause CreateKeyInfoClause(X509Certificate2 certificate, XmlDocument document)
        {
            const string algorithm = "http://www.w3.org/2000/09/xmldsig#sha1";
            if (Crypto.IsSupportedAlgorithm(algorithm))
            {
                var sha1 = Crypto.CreateHashAlgorithm(algorithm);
                var securityTokenReference = document.CreateElement(WsSecurityConstants.WsSecurity10.Prefix, "SecurityTokenReference", WsSecurityConstants.WsSecurity10.Namespace);
                var keyIdentifier = document.CreateElement(WsSecurityConstants.WsSecurity10.Prefix, "KeyIdentifier", WsSecurityConstants.WsSecurity10.Namespace);
                keyIdentifier.SetAttribute("ValueType", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1");
                keyIdentifier.InnerText = Convert.ToBase64String(sha1.ComputeHash(certificate.GetCertHash())); securityTokenReference.AppendChild(keyIdentifier);
                return new KeyInfoNode(securityTokenReference);
            }
            else
            {
                return new KeyInfoX509Data(certificate, X509IncludeOption.None);
            }
        }
        private SymmetricAlgorithm GetSymmetricAlgorithm(string algorithm)
        {
            if (_credentials?.Key is SymmetricSecurityKey symmetric)
                return SymmetricAlgorithmProvider.GetSymmetricAlgorithm(algorithm, symmetric);
            return SymmetricAlgorithmProvider.GetSymmetricAlgorithm(algorithm);
        }

        // shim
        abstract class WsSecurityConstants
        {
            public abstract string Prefix { get; }
            public abstract string Namespace { get; }

            public static readonly WsSecurityConstants WsSecurity10 = new WsSecurity10Constants();

            public class WsSecurity10Constants : WsSecurityConstants
            {
                public override string Prefix => "wsse";

                public override string Namespace => "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
            }
        }
    }
}

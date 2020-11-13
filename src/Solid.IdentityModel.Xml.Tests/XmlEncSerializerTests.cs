using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Xml;
using Solid.IdentityModel.Tokens;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;
using Xunit;

namespace Solid.IdentityModel.Xml.Tests
{
    public class XmlEncSerializerTests
    {
        static readonly string Sibling = nameof(Sibling);

        static XmlEncSerializerTests()
        {
            IdentityModelEventSource.ShowPII = true;
            CryptoProviderFactory.Default = new ServiceCollection()
                .AddCustomCryptoProvider(options => options.AddFullSupport())
                .BuildServiceProvider()
                .GetService<CryptoProviderFactory>()
            ;
        }

        [Theory]
        [InlineData("My value")]
        [InlineData("Another value")]
        [InlineData("Value")]
        public void ShouldWriteCipherData(string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);

            var data = new CipherData
            {
                CipherValue = bytes
            };

            var serializer = new TestableXmlEncSerializer();
            var element = GetElement(writer => serializer.WriteCipherDataPublic(writer, data));

            AssertCipherData(element, bytes);
        }

        [Theory]
        [InlineData("My value")]
        [InlineData("Another value")]
        [InlineData("Value")]
        public void ShouldReadCipherData(string value)
        {
            var expected = Encoding.UTF8.GetBytes(value);
            var xmlBuilder = new StringBuilder();
            xmlBuilder.Append("<CipherData xmlns=\"http://www.w3.org/2001/04/xmlenc#\">");
            xmlBuilder.Append($"<CipherValue>{Convert.ToBase64String(expected)}</CipherValue>");
            xmlBuilder.Append("</CipherData>");
            var xml = xmlBuilder.ToString();
            using (var reader = CreateReader(xml))
            {
                var serializer = new TestableXmlEncSerializer();

                Assert.True(serializer.TryReadCipherDataPublic(reader, out var data));
                Assert.Equal(expected, data.CipherValue);
                Assert.Equal(Sibling, reader.LocalName);
            }
        }

        [Theory]
        [InlineData("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p")]
        public void ShouldWriteEncryptionMethod(string encryptionAlgorithm)
        {
            var method = new EncryptionMethod(encryptionAlgorithm);

            var serializer = new TestableXmlEncSerializer();
            var element = GetElement(writer => serializer.WriteEncryptionMethodPublic(writer, method));

            AssertEncryptionMethod(element, encryptionAlgorithm);
            Assert.Empty(element.ChildNodes);
        }

        [Theory]
        [InlineData("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p")]
        public void ShouldReadEncryptionMethod(string encryptionAlgorithm)
        {
            var xml = $"<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" Algorithm=\"{encryptionAlgorithm}\" />";
            using (var reader = CreateReader(xml))
            {
                var serializer = new TestableXmlEncSerializer();

                Assert.True(serializer.TryReadEncryptionMethodPublic(reader, out var data));
                Assert.Equal(encryptionAlgorithm, data.Algorithm);
                Assert.Null(data.DigestMethod);
                Assert.Equal(Sibling, reader.LocalName);
            }
        }

        [Theory]
        [InlineData("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", "http://www.w3.org/2000/09/xmldsig#sha1")]
        public void ShouldWriteEncryptionMethodWithDigest(string encryptionAlgorithm, string digestAlgorithm)
        {
            var method = new EncryptionMethod(encryptionAlgorithm)
            {
                DigestMethod = new DigestMethod(digestAlgorithm)
            };

            var serializer = new TestableXmlEncSerializer();
            var element = GetElement(writer => serializer.WriteEncryptionMethodPublic(writer, method));

            AssertEncryptionMethod(element, encryptionAlgorithm);
            Assert.Single(element.ChildNodes);
            Assert.IsType<XmlElement>(element.FirstChild);

            var child = element.FirstChild as XmlElement;
            AssertDigestMethod(child, digestAlgorithm);
            Assert.Empty(child.ChildNodes);
        }

        [Theory]
        [InlineData("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", "http://www.w3.org/2000/09/xmldsig#sha1")]
        public void ShouldReadEncryptionMethodWithDigest(string encryptionAlgorithm, string digestAlgorithm)
        {
            var xmlBuilder = new StringBuilder();
            xmlBuilder.Append($"<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" Algorithm=\"{encryptionAlgorithm}\">");
            xmlBuilder.Append($"<DigestMethod xmlns=\"http://www.w3.org/2000/09/xmldsig#\" Algorithm=\"{digestAlgorithm}\" />");
            xmlBuilder.Append("</EncryptionMethod>");
            var xml = xmlBuilder.ToString();
            using (var reader = CreateReader(xml))
            {
                var serializer = new TestableXmlEncSerializer();

                Assert.True(serializer.TryReadEncryptionMethodPublic(reader, out var data));
                Assert.Equal(encryptionAlgorithm, data.Algorithm);
                Assert.Equal(data.DigestMethod?.Algorithm, digestAlgorithm);
                Assert.Equal(Sibling, reader.LocalName);
            }
        }

        [Theory]
        [InlineData("http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1", "GdAB+K/AJCgNzGaBXiXr1b0n6Pk=")]
        public void ShouldWriteSecurityTokenReference(string valueType, string value)
        {
            var keyInfo = new ExtendedKeyInfo
            {
                SecurityTokenReference = new SecurityTokenReference
                {
                    KeyIdentifier = new KeyIdentifier
                    {
                        ValueType = valueType,
                        Value = value
                    }
                }
            };

            var serializer = new TestableXmlEncSerializer();
            var element = GetElement(writer => serializer.WriteKeyInfoPublic(writer, keyInfo));

            AssertKeyInfo(element);

            var securityTokenReference = element.FirstChild as XmlElement;
            AssertSecurityTokenReference(securityTokenReference);

            var keyIdentifier = securityTokenReference.FirstChild as XmlElement;
            AssertKeyIdentifier(keyIdentifier, valueType, value);
        }

        [Theory]
        [InlineData("http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1", "GdAB+K/AJCgNzGaBXiXr1b0n6Pk=")]
        public void ShouldReadSecurityTokenReference(string valueType, string value)
        {
            var xmlBuilder = new StringBuilder();
            xmlBuilder.Append("<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">");
            xmlBuilder.Append("<SecurityTokenReference xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">");
            xmlBuilder.Append($"<KeyIdentifier ValueType=\"{valueType}\">{value}</KeyIdentifier>");
            xmlBuilder.Append("</SecurityTokenReference>");
            xmlBuilder.Append("</KeyInfo>");
            var xml = xmlBuilder.ToString();
            using (var reader = CreateReader(xml))
            {
                var serializer = new TestableXmlEncSerializer();

                Assert.True(serializer.TryReadKeyInfoPublic(reader, out var info));
                Assert.IsType<ExtendedKeyInfo>(info);
                var extended = info as ExtendedKeyInfo;
                Assert.Equal(valueType, extended.SecurityTokenReference.KeyIdentifier.ValueType);
                Assert.Equal(value, extended.SecurityTokenReference.KeyIdentifier.Value);
                Assert.Equal(Sibling, reader.LocalName);
            }
        }

        [Fact]
        public void ShouldWriteEncryptedKey()
        {
            var bytes = Guid.NewGuid().ToByteArray();
            var keyInfo = new ExtendedKeyInfo
            {
                EncryptedKey = new EncryptedKey
                {
                    EncryptionMethod = new EncryptionMethod("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"),
                    KeyInfo = new ExtendedKeyInfo
                    {
                        SecurityTokenReference = new SecurityTokenReference
                        {
                            KeyIdentifier = new KeyIdentifier()
                        }
                    },
                    CipherData = new CipherData
                    {
                        CipherValue = bytes
                    }
                }
            };

            var serializer = new TestableXmlEncSerializer();
            var element = GetElement(writer => serializer.WriteKeyInfoPublic(writer, keyInfo));

            AssertKeyInfo(element);

            var encryptedKey = element.FirstChild as XmlElement;
            Assert.Equal("xenc", encryptedKey.Prefix);
            Assert.Equal("EncryptedKey", encryptedKey.LocalName);
            Assert.Equal("http://www.w3.org/2001/04/xmlenc#", encryptedKey.NamespaceURI);

            Assert.Collection(encryptedKey.ChildNodes.OfType<XmlElement>(),
                child =>
                {
                    AssertEncryptionMethod(child, "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
                    Assert.Empty(child.ChildNodes);
                },
                child =>
                {
                    AssertKeyInfo(child);
                    AssertSecurityTokenReference(child.FirstChild as XmlElement);
                },
                child =>
                {
                    AssertCipherData(child, bytes);
                }
            );
        }

        [Fact]
        public void ShouldReadEncryptedKey()
        {
            var xmlBuilder = new StringBuilder();
            xmlBuilder.Append("<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">");
            xmlBuilder.Append("<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">");
            xmlBuilder.Append("<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\" />");
            xmlBuilder.Append("<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">");
            xmlBuilder.Append("<SecurityTokenReference xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" />");
            xmlBuilder.Append("</KeyInfo>");
            xmlBuilder.Append("<CipherData>");
            xmlBuilder.Append($"<CipherValue>{Convert.ToBase64String(Encoding.UTF8.GetBytes(nameof(ShouldReadEncryptedKey)))}</CipherValue>");
            xmlBuilder.Append("</CipherData>");
            xmlBuilder.Append("</EncryptedKey>");
            xmlBuilder.Append("</KeyInfo>");
            var xml = xmlBuilder.ToString();
            using (var reader = CreateReader(xml))
            {
                var serializer = new TestableXmlEncSerializer();

                Assert.True(serializer.TryReadKeyInfoPublic(reader, out var info));
                Assert.IsType<ExtendedKeyInfo>(info);
                var extended = info as ExtendedKeyInfo;
                Assert.Null(extended.SecurityTokenReference);
                Assert.NotNull(extended.EncryptedKey);
                var encrypted = extended.EncryptedKey;
                Assert.NotNull(encrypted.EncryptionMethod);
                Assert.NotNull(encrypted.CipherData);
                Assert.NotNull(encrypted.KeyInfo);
                Assert.Equal(Sibling, reader.LocalName);
            }
        }

        private void AssertCipherData(XmlElement element, byte[] value)
            => AssertCipherData(element, Convert.ToBase64String(value));

        private void AssertCipherData(XmlElement element, string value)
        {
            Assert.Equal("xenc", element.Prefix);
            Assert.Equal("CipherData", element.LocalName);
            Assert.Equal("http://www.w3.org/2001/04/xmlenc#", element.NamespaceURI);

            Assert.Single(element.ChildNodes);
            var child = element.FirstChild;
            Assert.Equal("xenc", child.Prefix);
            Assert.Equal("CipherValue", child.LocalName);
            Assert.Equal("http://www.w3.org/2001/04/xmlenc#", child.NamespaceURI);
            Assert.Equal(value, child.InnerText);
        }

        private void AssertKeyIdentifier(XmlElement element, string valueType, string value)
        {
            Assert.Equal("wsse", element.Prefix);
            Assert.Equal("KeyIdentifier", element.LocalName);
            Assert.Equal(valueType, element.GetAttribute("ValueType"));
            Assert.Equal("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", element.NamespaceURI);
            Assert.Equal(value, element.InnerText);
        }

        private void AssertSecurityTokenReference(XmlElement element)
        {
            Assert.Equal("wsse", element.Prefix);
            Assert.Equal("SecurityTokenReference", element.LocalName);
            Assert.Equal("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", element.NamespaceURI);
            Assert.Single(element.ChildNodes);
            Assert.IsType<XmlElement>(element.FirstChild);
        }

        private void AssertKeyInfo(XmlElement element)
        {
            Assert.Equal("ds", element.Prefix);
            Assert.Equal("KeyInfo", element.LocalName);
            Assert.Equal("http://www.w3.org/2000/09/xmldsig#", element.NamespaceURI);
            Assert.Single(element.ChildNodes);
            Assert.IsType<XmlElement>(element.FirstChild);
        }

        private void AssertEncryptionMethod(XmlElement element, string algorithm)
        {
            Assert.Equal("xenc", element.Prefix);
            Assert.Equal("EncryptionMethod", element.LocalName);
            Assert.Equal("http://www.w3.org/2001/04/xmlenc#", element.NamespaceURI);
            Assert.Equal(algorithm, element.GetAttribute("Algorithm"));
        }

        private void AssertDigestMethod(XmlElement element, string algorithm)
        {
            Assert.Equal("ds", element.Prefix);
            Assert.Equal("DigestMethod", element.LocalName);
            Assert.Equal("http://www.w3.org/2000/09/xmldsig#", element.NamespaceURI);
            Assert.Equal(algorithm, element.GetAttribute("Algorithm"));
        }

        private XmlReader CreateReader(string xml)
        {
            var builder = new StringBuilder();
            builder.Append("<Wrapper>");
            builder.Append(xml);

            builder.Append($"<{Sibling} />");
            builder.Append("</Wrapper>");

            var stream = new MemoryStream(Encoding.UTF8.GetBytes(builder.ToString()));
            var reader = XmlReader.Create(stream);
            reader.MoveToContent();
            reader.Read();
            return reader;
        }

        private XmlElement GetElement(Action<XmlWriter> action)
        {
            using(var stream = new MemoryStream())
            {
                using (var writer = XmlWriter.Create(stream, new XmlWriterSettings { CloseOutput = false, OmitXmlDeclaration = true }))
                    action(writer);
                stream.Position = 0;

                var document = new XmlDocument();
                document.Load(stream);
                return document.DocumentElement;
            }
        }
    }

    class TestableXmlEncSerializer : XmlEncSerializer
    {
        public bool TryReadCipherDataPublic(XmlReader reader, out CipherData data)
            => TryReadCipherData(reader, out data);

        public bool TryReadEncryptionMethodPublic(XmlReader reader, out EncryptionMethod data)
           => TryReadEncryptionMethod(reader, out data);

        public bool TryReadKeyInfoPublic(XmlReader reader, out ExtendedKeyInfo keyInfo)
            => TryReadKeyInfo(reader, out keyInfo);

        public void WriteCipherDataPublic(XmlWriter writer, CipherData data)
            => WriteCipherData(writer, data);

        public void WriteEncryptionMethodPublic(XmlWriter writer, EncryptionMethod method)
            => WriteEncryptionMethod(writer, method);

        public void WriteKeyInfoPublic(XmlWriter writer, ExtendedKeyInfo keyInfo)
            => WriteKeyInfo(writer, keyInfo);
    }
}

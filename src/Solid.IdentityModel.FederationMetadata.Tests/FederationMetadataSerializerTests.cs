using Solid.IdentityModel.Tokens.Saml2.Metadata;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;
using Xunit;

namespace Solid.IdentityModel.FederationMetadata.Tests
{
    public class FederationMetadataSerializerTests
    {
        private TestMetadataSerializer _serializer;

        public FederationMetadataSerializerTests()
        {
            _serializer = new TestMetadataSerializer();
        }

        [Fact]
        public void ShouldReadExampleWithSecurityTokenService()
        {
            var reader = CreateReader(ExampleMetadata.UnsignedExampleSecurityTokenService);
            var metadata = _serializer.ReadMetadata(reader);
            Assert.IsType<EntityDescriptor>(metadata);
            Assert.True(reader.EOF);
            Assert.Equal(1, metadata.Items.Count);
            Assert.IsType<SecurityTokenServiceDescriptor>(metadata.Items.First());
        }

        [Theory]
        [InlineData(typeof(AttributeServiceDescriptor))]
        [InlineData(typeof(ApplicationServiceDescriptor))]
        [InlineData(typeof(PseudonymServiceDescriptor))]
        [InlineData(typeof(SecurityTokenServiceDescriptor))]
        public void ShouldReadCorrectRoleType(Type descriptorType)
        {
            var typeName = $"{descriptorType.Name.Replace("Descriptor", string.Empty)}Type";
            var xml = @$"
<RoleDescriptor 
  xmlns=""urn:oasis:names:tc:SAML:2.0:metadata""
  xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706""
  xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
  xsi:type=""fed:{typeName}""
>
</RoleDescriptor>";

            var reader = CreateReader(xml);
            var metadata = _serializer.ReadRoleDescriptor(reader);
            Assert.IsType(descriptorType, metadata);
        }

        private XmlDictionaryReader CreateReader(string xml)
        {
            var stream = new MemoryStream(new UTF8Encoding(false).GetBytes(xml));
            var reader = XmlReader.Create(stream);
            reader.MoveToContent();
            return XmlDictionaryReader.CreateDictionaryReader(reader);
        }

        class TestMetadataSerializer : FederationMetadataSerializer
        {
            public RoleDescriptor ReadRoleDescriptor(XmlReader reader)
            {
                if (TryReadRoleDescriptor(CreateXmlDictionaryReader(reader), out var role))
                    return role;
                return null;
            }

            private XmlDictionaryReader CreateXmlDictionaryReader(XmlReader reader) => XmlDictionaryReader.CreateDictionaryReader(reader);
        }
    }
}

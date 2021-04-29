using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using Solid.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Xunit;

namespace Solid.IdentityModel.Tokens.Saml.Tests
{
    public class HolderOfKeysTests : IClassFixture<SamlTestFixture>
    {
        private SamlTestFixture _fixture;

        static HolderOfKeysTests()
        {
            IdentityModelEventSource.ShowPII = true;

            var services = new ServiceCollection()
                .AddCustomCryptoProvider(options => options.AddFullSupport())
                .BuildServiceProvider()
            ;

            CryptoProviderFactory.Default = services.GetRequiredService<CryptoProviderFactory>();
        }

        public HolderOfKeysTests(SamlTestFixture fixture)
        {
            _fixture = fixture;
        }

        [Fact]
        public void ShouldAddHolderOfKeyConfirmation()
        {
            var proof = new byte[32];
            RandomNumberGenerator.Fill(proof);
            var proofKey = new SymmetricSecurityKey(proof);

            var handler = new ExtendedSaml2SecurityTokenHandler();
            var descriptor = _fixture.CreateDescriptor(proofKey: proofKey);
            descriptor.EncryptingCredentials = null;

            var token = handler.CreateToken(descriptor);

            Assert.NotNull(token);
            Assert.IsAssignableFrom<Saml2SecurityToken>(token);

            _fixture.AssertContainsSymmetricKey(token, proofKey);
        }

        [Fact]
        public void ShouldWriteUnencryptedHolderOfKeyConfirmation()
        {
            var proof = new byte[32];
            RandomNumberGenerator.Fill(proof);
            var proofKey = new SymmetricSecurityKey(proof);

            var handler = new ExtendedSaml2SecurityTokenHandler();
            var descriptor = _fixture.CreateDescriptor(proofKey: proofKey, encryptProofKey: false);
            descriptor.EncryptingCredentials = null;

            var token = handler.CreateToken(descriptor);

            using (var stream = new MemoryStream())
            {
                using (var writer = XmlWriter.Create(stream, new XmlWriterSettings { CloseOutput = false }))
                    handler.WriteToken(writer, token);
                stream.Position = 0;

                var document = XDocument.Load(stream);
                var subjectConfirmation = document.Descendants(XName.Get(Saml2Constants.Elements.SubjectConfirmation, Saml2Constants.Namespace)).SingleOrDefault();
                var method = subjectConfirmation.Attribute(Saml2Constants.Attributes.Method);

                Assert.Equal(Saml2Constants.ConfirmationMethods.HolderOfKeyString, method.Value);

                var secret = subjectConfirmation
                    ?.Elements(XName.Get(Saml2Constants.Elements.SubjectConfirmationData, Saml2Constants.Namespace)).SingleOrDefault()
                    ?.Elements(XName.Get(XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace)).SingleOrDefault()
                    ?.Elements(XName.Get(WsTrustElements.BinarySecret, WsTrustConstants.Trust13.Namespace)).SingleOrDefault();
                Assert.NotNull(secret);
                Assert.Equal(Convert.ToBase64String(proof), secret.Value);
            }
        }

        [Fact]
        public void ShouldWriteEncryptedHolderOfKeyConfirmation()
        {
            var proof = new byte[32];
            RandomNumberGenerator.Fill(proof);
            var proofKey = new SymmetricSecurityKey(proof);

            var handler = new ExtendedSaml2SecurityTokenHandler();
            var descriptor = _fixture.CreateDescriptor(proofKey: proofKey);
            descriptor.EncryptingCredentials = null;

            var token = handler.CreateToken(descriptor);

            using (var stream = new MemoryStream())
            {
                using (var writer = XmlWriter.Create(stream, new XmlWriterSettings { CloseOutput = false }))
                    handler.WriteToken(writer, token);
                stream.Position = 0;

                var document = XDocument.Load(stream);
                var subjectConfirmation = document.Descendants(XName.Get(Saml2Constants.Elements.SubjectConfirmation, Saml2Constants.Namespace)).SingleOrDefault();
                var method = subjectConfirmation.Attribute(Saml2Constants.Attributes.Method);

                Assert.Equal(Saml2Constants.ConfirmationMethods.HolderOfKeyString, method.Value);
                var subjectConfirmationData = subjectConfirmation
                    ?.Elements(XName.Get(Saml2Constants.Elements.SubjectConfirmationData, Saml2Constants.Namespace)).SingleOrDefault();

                Assert.NotNull(subjectConfirmationData);
                Assert.Equal($"saml:{Saml2Constants.Types.KeyInfoConfirmationDataType}", subjectConfirmationData.Attribute(XName.Get("Type", "http://www.w3.org/2001/XMLSchema-instance"))?.Value);

                var encryptedKeyInfo = subjectConfirmationData
                    ?.Elements(XName.Get(XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace)).SingleOrDefault()
                    ?.Elements(XName.Get("EncryptedKey", "http://www.w3.org/2001/04/xmlenc#")).SingleOrDefault();
                Assert.NotNull(encryptedKeyInfo);
            }
        }

        [Fact]
        public void ShouldRoundTripEncryptedHolderOfKeyConfirmation()
        {
            var proof = new byte[32];
            RandomNumberGenerator.Fill(proof);
            var proofKey = new SymmetricSecurityKey(proof);

            var handler = new ExtendedSaml2SecurityTokenHandler();
            var descriptor = _fixture.CreateDescriptor(proofKey: proofKey);
            descriptor.EncryptingCredentials = null;

            var token = handler.CreateToken(descriptor);

            using (var stream = new MemoryStream())
            {
                using (var writer = XmlWriter.Create(stream, new XmlWriterSettings { CloseOutput = false }))
                    handler.WriteToken(writer, token);
                stream.Position = 0;
                using (var reader = XmlReader.Create(stream))
                {
                    var parameters = _fixture.CreateTokenValidationParameters(validateLifetime: true);
                    var user = handler.ValidateToken(reader, parameters, out var validatedToken);

                    Assert.NotNull(user);
                    Assert.NotNull(validatedToken);
                    _fixture.AssertContainsSymmetricKey(validatedToken, proofKey);
                }
            }
        }

        [Fact]
        public void ShouldRoundTripUnencryptedHolderOfKeyConfirmation()
        {
            var proof = new byte[32];
            RandomNumberGenerator.Fill(proof);
            var proofKey = new SymmetricSecurityKey(proof);

            var handler = new ExtendedSaml2SecurityTokenHandler();
            var descriptor = _fixture.CreateDescriptor(proofKey: proofKey, encryptProofKey: false);
            descriptor.EncryptingCredentials = null;

            var token = handler.CreateToken(descriptor);

            using (var stream = new MemoryStream())
            {
                using (var writer = XmlWriter.Create(stream, new XmlWriterSettings { CloseOutput = false }))
                    handler.WriteToken(writer, token);
                stream.Position = 0;
                using (var reader = XmlReader.Create(stream))
                {
                    var parameters = _fixture.CreateTokenValidationParameters(validateLifetime: true);
                    var user = handler.ValidateToken(reader, parameters, out var validatedToken);

                    Assert.NotNull(user);
                    Assert.NotNull(validatedToken);
                    _fixture.AssertContainsSymmetricKey(validatedToken, proofKey);
                }
            }
        }
    }
}

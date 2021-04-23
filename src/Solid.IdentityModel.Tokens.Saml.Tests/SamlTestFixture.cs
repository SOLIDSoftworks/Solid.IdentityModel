﻿using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace Solid.IdentityModel.Tokens.Saml.Tests
{
    public class SamlTestFixture : IDisposable
    {
        private RSA _encryptingAlgorithm;
        private RSA _signingAlgorithm;
        private readonly Lazy<SecurityKey> _lazySigningKey;
        private readonly Lazy<SecurityKey> _lazySignatureVerificationKey;
        private readonly Lazy<SecurityKey> _lazyEncryptionKey;
        private readonly Lazy<SecurityKey> _lazyDecryptionKey;

        public SecurityKey DefaultSigningKey => _lazySigningKey.Value;
        public SecurityKey DefaultSignatureVerificationKey => _lazySignatureVerificationKey.Value;
        public SecurityKey DefaultEncryptionKey => _lazyEncryptionKey.Value;
        public SecurityKey DefautDecryptionKey => _lazyDecryptionKey.Value;

        public SamlTestFixture()
        {
            _encryptingAlgorithm = RSA.Create(2048);
            _signingAlgorithm = RSA.Create(2048);

            _lazySigningKey = new Lazy<SecurityKey>(() => new RsaSecurityKey(_signingAlgorithm), LazyThreadSafetyMode.ExecutionAndPublication);
            _lazySignatureVerificationKey = new Lazy<SecurityKey>(() =>
            {
                var bytes = _signingAlgorithm.ExportRSAPublicKey();
                var rsa = RSA.Create();
                rsa.ImportRSAPublicKey(bytes, out _);
                return new RsaSecurityKey(rsa);
            }, LazyThreadSafetyMode.ExecutionAndPublication);
            _lazyDecryptionKey = new Lazy<SecurityKey>(() => new RsaSecurityKey(_signingAlgorithm), LazyThreadSafetyMode.ExecutionAndPublication);
            _lazyEncryptionKey = new Lazy<SecurityKey>(() =>
            {
                var bytes = _signingAlgorithm.ExportRSAPublicKey();
                var rsa = RSA.Create();
                rsa.ImportRSAPublicKey(bytes, out _);
                return new RsaSecurityKey(rsa);
            }, LazyThreadSafetyMode.ExecutionAndPublication);
        }

        public void Dispose()
        {
            _signingAlgorithm?.Dispose();
            _encryptingAlgorithm?.Dispose();
        }

        public TokenValidationParameters CreateTokenValidationParameters(SecurityKey decryptionKey = null, SecurityKey signatureVerificationKey = null, bool validateLifetime = false)
        {
            if (decryptionKey == null)
                decryptionKey = DefautDecryptionKey;
            if (signatureVerificationKey == null)
                signatureVerificationKey = DefaultSignatureVerificationKey;
            var parameters = new TokenValidationParameters
            {
                TokenDecryptionKey = decryptionKey,
                IssuerSigningKey = signatureVerificationKey,
                ValidateLifetime = validateLifetime,
                ValidateAudience = false,
                ValidateIssuer = false
            };
            return parameters;
        }

        public SecurityTokenDescriptor CreateDescriptor(string name = "user", string nameIdentifier = "user-id", SecurityKey encryptionKey = null, SecurityKey signingKey = null, SecurityKey proofKey = null, SecurityKey proofKeyEncryptionKey = null)
        {
            if (encryptionKey == null)
                encryptionKey = DefaultEncryptionKey;
            if (signingKey == null)
                signingKey = DefaultSigningKey;
            var claims = new List<Claim>();

            if (name != null)
                claims.Add(new Claim(ClaimTypes.Name, name));
            if (nameIdentifier != null)
                claims.Add(new Claim(ClaimTypes.NameIdentifier, nameIdentifier));

            var identity = new ClaimsIdentity(claims, "Test", ClaimTypes.NameIdentifier, ClaimTypes.Role);

            var descriptor = new RequestedSecurityTokenDescriptor
            {
                Issuer = "urn:tests",
                Audience = "urn:unittests",
                EncryptingCredentials = new EncryptingCredentials(encryptionKey, SecurityAlgorithms.RsaOaepKeyWrap, SecurityAlgorithms.Aes128Encryption),
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest),
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddMinutes(5),
                NotBefore = DateTime.UtcNow,
                Subject = identity,
                ProofKey = proofKey
            };

            return descriptor;
        }

        private X509Certificate2 GenerateCertificate(DateTime? notBefore = null, DateTime? notAfter = null)
        {
            var name = Guid.NewGuid().ToString("N");
            var builder = new SubjectAlternativeNameBuilder();
            builder.AddDnsName(name);

            var dn = new X500DistinguishedName($"CN={name}");
            using (var rsa = RSA.Create(2048))
            {
                var request = new CertificateRequest(dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                var usage = new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement, true);
                request.CertificateExtensions.Add(usage);

                var oids = new OidCollection
                {
                    new Oid("1.3.6.1.5.5.7.3.1"), // Server authentication
                    new Oid("1.3.6.1.5.5.7.3.2") // Client authentication
                };

                request.CertificateExtensions.Add(
                   new X509EnhancedKeyUsageExtension(oids, false));

                request.CertificateExtensions.Add(builder.Build());

                var certificate = request.CreateSelfSigned(new DateTimeOffset(notBefore ?? DateTime.UtcNow.AddMinutes(-5)), new DateTimeOffset(notAfter ?? DateTime.UtcNow.AddMinutes(5)));
                var bytes = certificate.Export(X509ContentType.Pfx);
                return new X509Certificate2(bytes, null as string, X509KeyStorageFlags.Exportable); // don't ask me why, but this is required for some tests to work; i.e. Mtls tests
            }
        }
    }
}

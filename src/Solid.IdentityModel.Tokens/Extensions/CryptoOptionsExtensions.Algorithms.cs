using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Solid.IdentityModel.Tokens.Crypto;
using Solid.IdentityModel.Tokens.Crypto.Providers.Signature;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Solid.IdentityModel.Tokens
{
    public static class CryptoOptionsExtensions_Algorithms
    {
        public static CryptoOptions AddFullSupport(this CryptoOptions options)
            => options
                .AddSha1Support()
                .AddRsaWithSha1Support()
                .MapKeyWrapAlgorithm(SecurityAlgorithms.RsaOaepKeyWrap, SecurityAlgorithms.RsaOAEP)
                .MapKeyWrapAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", SecurityAlgorithms.RsaOAEP)

                .AddAes128CbcSupport()
                .AddAes192CbcSupport()
                .AddAes256CbcSupport()
        ;

        public static CryptoOptions AddAes128CbcSupport(this CryptoOptions options)
            => options.AddAesSupport(SecurityAlgorithms.Aes128Encryption, 128, CipherMode.CBC)
        ;

        public static CryptoOptions AddAes192CbcSupport(this CryptoOptions options)
            => options.AddAesSupport(SecurityAlgorithms.Aes192Encryption, 192, CipherMode.CBC)
        ;

        public static CryptoOptions AddAes256CbcSupport(this CryptoOptions options)
            => options.AddAesSupport(SecurityAlgorithms.Aes256Encryption, 256, CipherMode.CBC)
        ;

        public static CryptoOptions AddSha1Support(this CryptoOptions options)
            => options
            .AddSupportedHashAlgorithm("SHA1", _ => SHA1.Create())
            .MapHashAlgorithm("http://www.w3.org/2000/09/xmldsig#sha1", "SHA1")
        ;

        public static CryptoOptions AddRsaWithSha1Support(this CryptoOptions options)
            => options
            .AddSupportedSignatureAlgorithm("RS1", (services, key) =>
            {
                var logger = services.GetRequiredService<ILogger<RsaSignatureProvider>>();
                return new RsaSignatureProvider(key, "RS1", HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1, logger);
            })
            .MapSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1", "RS1")
        ;

        private static CryptoOptions AddAesSupport(this CryptoOptions options, string algorithm, int keySize, CipherMode mode)
            => options
            .AddSupportedSymmetricAlgorithm(algorithm, _ =>
            {
                var aes = Aes.Create();
                aes.Mode = mode;
                aes.KeySize = keySize;
                return aes;
            })
        ;
    }
}

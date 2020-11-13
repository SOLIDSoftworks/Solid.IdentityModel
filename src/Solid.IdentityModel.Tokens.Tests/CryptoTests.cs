using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using Xunit;

namespace Solid.IdentityModel.Tokens.Tests
{
    public class CryptoTests
    {
        public static readonly string CertificateBase64 = "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";

        static CryptoTests()
        {
            IdentityModelEventSource.ShowPII = true;
        }


        [Theory]
        [InlineData("http://www.w3.org/2000/09/xmldsig#sha1")]
        [InlineData(SecurityAlgorithms.Sha256Digest)]
        [InlineData(SecurityAlgorithms.Sha384Digest)]
        [InlineData(SecurityAlgorithms.Sha512Digest)]
        [InlineData("SHA1")]
        [InlineData(SecurityAlgorithms.Sha256)]
        [InlineData(SecurityAlgorithms.Sha384)]
        [InlineData(SecurityAlgorithms.Sha512)]
        public void ShouldSupportHashAlgorithm(string algorithm)
        {
            var crypto = CreateCryptoProviderFactory();
            Assert.True(crypto.IsSupportedAlgorithm(algorithm));
        }


        [Theory]
        [InlineData("http://www.w3.org/2000/09/xmldsig#rsa-sha1")]
        [InlineData(SecurityAlgorithms.RsaSha256Signature)]
        [InlineData(SecurityAlgorithms.RsaSha384Signature)]
        [InlineData(SecurityAlgorithms.RsaSha512Signature)]
        [InlineData("RS1")]
        [InlineData(SecurityAlgorithms.RsaSha256)]
        [InlineData(SecurityAlgorithms.RsaSha384)]
        [InlineData(SecurityAlgorithms.RsaSha512)]
        public void ShouldSupportAsymmetricSignatureAlgorithm(string algorithm)
        {
            var certificate = new X509Certificate2(Convert.FromBase64String(CertificateBase64));
            var key = new X509SecurityKey(certificate);
            var crypto = CreateCryptoProviderFactory();
            Assert.True(crypto.IsSupportedAlgorithm(algorithm, key));
        }
        
        [Theory]
        [InlineData("http://www.w3.org/2000/09/xmldsig#hmac-sha1")]
        [InlineData(SecurityAlgorithms.HmacSha256Signature)]
        [InlineData(SecurityAlgorithms.HmacSha384Signature)]
        [InlineData(SecurityAlgorithms.HmacSha512Signature)]
        [InlineData("H1")]
        [InlineData(SecurityAlgorithms.HmacSha256)]
        [InlineData(SecurityAlgorithms.HmacSha384)]
        [InlineData(SecurityAlgorithms.HmacSha512)]
        public void ShouldSupportSymmetricSignatureAlgorithm(string algorithm)
        {
            var bytes = new byte[16];
            var random = RandomNumberGenerator.Create();
            random.GetNonZeroBytes(bytes);
            var key = new SymmetricSecurityKey(bytes);
            var crypto = CreateCryptoProviderFactory();
            Assert.True(crypto.IsSupportedAlgorithm(algorithm, key));
            var s = crypto.CreateForSigning(key, algorithm);
        }

        [Theory]
        [InlineData(SecurityAlgorithms.RsaOAEP)]
        [InlineData(SecurityAlgorithms.RsaOaepKeyWrap)]
        [InlineData("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p")]
        public void ShouldSupportKeyWrapAlgorithm(string algorithm)
        {
            var certificate = new X509Certificate2(Convert.FromBase64String(CertificateBase64));
            var key = new X509SecurityKey(certificate);
            var crypto = CreateCryptoProviderFactory();
            Assert.True(crypto.IsSupportedAlgorithm(algorithm, key));
        }

        [Theory]
        [InlineData("http://www.w3.org/2000/09/xmldsig#sha1", typeof(SHA1))]
        [InlineData(SecurityAlgorithms.Sha256Digest, typeof(SHA256))]
        [InlineData(SecurityAlgorithms.Sha384Digest, typeof(SHA384))]
        [InlineData(SecurityAlgorithms.Sha512Digest, typeof(SHA512))]
        public void ShouldGetHashAlgorithm(string algorithm, Type type)
        {
            var crypto = CreateCryptoProviderFactory();
            var hashAlgorithm = crypto.CreateHashAlgorithm(algorithm);

            Assert.NotNull(hashAlgorithm);
            Assert.IsAssignableFrom(type, hashAlgorithm);
        }

        [Theory]
        [MemberData(nameof(SignatureProviderTestData))]
        public void ShouldGetSignatureProvider(SignatureProviderTestData data)
        {
            var crypto = CreateCryptoProviderFactory();

            if (data.Sign)
            {
                var provider = crypto.CreateForSigning(data.SigningKey, data.Algorithm);
                Assert.NotNull(provider);
                var signed = Convert.ToBase64String(provider.Sign(Encoding.UTF8.GetBytes(data.Data)));
                Assert.Equal(data.SignedData, signed);
            }
            if (data.Verify)
            {
                var provider = crypto.CreateForVerifying(data.SigningKey, data.Algorithm);
                Assert.NotNull(provider);
                var verified = provider.Verify(Encoding.UTF8.GetBytes(data.Data), Convert.FromBase64String(data.SignedData));
                Assert.True(verified);
            }
        }

        [Theory]
        [MemberData(nameof(KeyWrapProviderTestData))]
        public void ShouldGetKeyWrapProvider(KeyWrapProviderTestData data)
        {
            var crypto = CreateCryptoProviderFactory();
            var wrapped = null as string;
            if (data.Wrap)
            {
                var provider = crypto.CreateKeyWrapProvider(data.SecurityKey, data.Algorithm);
                Assert.NotNull(provider);
                wrapped = Convert.ToBase64String(provider.WrapKey(Convert.FromBase64String(data.PlainText)));
            }
            if (data.Unwrap)
            {
                var provider = crypto.CreateKeyWrapProviderForUnwrap(data.SecurityKey, data.Algorithm);
                Assert.NotNull(provider);
                var unwrapped = Convert.ToBase64String(provider.UnwrapKey(Convert.FromBase64String(data.Wrapped)));
                Assert.Equal(data.PlainText, unwrapped);

                if(wrapped != null)
                {
                    var unwrapped2 = Convert.ToBase64String(provider.UnwrapKey(Convert.FromBase64String(wrapped)));
                    Assert.Equal(data.PlainText, unwrapped2);
                }
            }
        }

        [Theory]
        [MemberData(nameof(RsaKeyWrapInteropTestData))]
        public void ShouldInteropWithEncryptedXml(KeyWrapProviderTestData data)
        {
            var crypto = CreateCryptoProviderFactory();
            var wrapped = null as string;
            if (data.Wrap && data.Unwrap)
            {
                var provider = crypto.CreateKeyWrapProvider(data.SecurityKey, data.Algorithm);
                Assert.NotNull(provider);
                wrapped = Convert.ToBase64String(provider.WrapKey(Convert.FromBase64String(data.PlainText)));
            }
            if (data.Unwrap)
            {
                var provider = crypto.CreateKeyWrapProviderForUnwrap(data.SecurityKey, data.Algorithm);
                Assert.NotNull(provider);
                var unwrapped = Convert.ToBase64String(provider.UnwrapKey(Convert.FromBase64String(data.Wrapped)));
                Assert.Equal(data.PlainText, unwrapped);

                if (wrapped != null)
                {
                    var rsa = null as RSA;
                    if (data.SecurityKey is X509SecurityKey x509SecurityKey)
                        rsa = x509SecurityKey.Certificate.GetRSAPrivateKey();
                    if (data.SecurityKey is RsaSecurityKey rsaSecurityKey)
                        rsa = rsaSecurityKey.Rsa ?? RSA.Create(rsaSecurityKey.Parameters);
                    var unwrapped2 = Convert.ToBase64String(EncryptedXml.DecryptKey(Convert.FromBase64String(wrapped), rsa, true));
                    Assert.Equal(data.PlainText, unwrapped2);
                }
            }
        }

        public static TheoryData<KeyWrapProviderTestData> RsaKeyWrapInteropTestData
        {
            get
            {
                var certificate = new X509Certificate2(Convert.FromBase64String(CertificateBase64), null as string, X509KeyStorageFlags.Exportable);
                var privateKey = certificate.GetRSAPrivateKey();
                var publicKey = certificate.GetRSAPublicKey();
                var privateKeyParameters = privateKey.ExportParameters(true);
                var publicKeyParamters = publicKey.ExportParameters(false);

                var key = new byte[32];
                RandomNumberGenerator.Fill(key);
                var plainText = Convert.ToBase64String(key);

                var theoryData = new TheoryData<KeyWrapProviderTestData>();

                var data = new[]
                {
                    new KeyWrapData
                    {
                        Algorithms = new []
                        {
                            SecurityAlgorithms.RsaOAEP,
                            SecurityAlgorithms.RsaOaepKeyWrap,
                            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
                        }
                    }
                };

                foreach (var item in data)
                {
                    var wrapped = Convert.ToBase64String(EncryptedXml.EncryptKey(key, certificate.GetRSAPublicKey(), true));
                    foreach (var algorithm in item.Algorithms)
                    {
                        theoryData.Add(new KeyWrapProviderTestData
                        {
                            SecurityKey = new X509SecurityKey(certificate),
                            Algorithm = algorithm,
                            PlainText = plainText,
                            Wrapped = wrapped,
                            Unwrap = true,
                            Wrap = true
                        });
                        theoryData.Add(new KeyWrapProviderTestData
                        {
                            SecurityKey = new RsaSecurityKey(privateKey),
                            Algorithm = algorithm,
                            PlainText = plainText,
                            Wrapped = wrapped,
                            Unwrap = true,
                            Wrap = true
                        });
                        theoryData.Add(new KeyWrapProviderTestData
                        {
                            SecurityKey = new RsaSecurityKey(privateKeyParameters),
                            Algorithm = algorithm,
                            PlainText = plainText,
                            Wrapped = wrapped,
                            Unwrap = true,
                            Wrap = true
                        });
                    }
                }
                return theoryData;
            }
        }

        public static TheoryData<KeyWrapProviderTestData> KeyWrapProviderTestData
        {
            get
            {
                var certificate = new X509Certificate2(Convert.FromBase64String(CertificateBase64), null as string, X509KeyStorageFlags.Exportable);
                var privateKey = certificate.GetRSAPrivateKey();
                var publicKey = certificate.GetRSAPublicKey();
                var privateKeyParameters = privateKey.ExportParameters(true);
                var publicKeyParamters = publicKey.ExportParameters(false);

                var key = new byte[32];
                RandomNumberGenerator.Fill(key);
                var plainText = Convert.ToBase64String(key);

                var theoryData = new TheoryData<KeyWrapProviderTestData>();

                var data = new[]
                {
                    new KeyWrapData
                    {
                        Algorithms = new []
                        {
                            SecurityAlgorithms.RsaOAEP,
                            SecurityAlgorithms.RsaOaepKeyWrap,
                            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
                        }
                    }
                };

                foreach(var item in data)
                {
                    var provider = new RsaKeyWrapProvider(new X509SecurityKey(certificate), SecurityAlgorithms.RsaOAEP, false);
                    var wrapped = Convert.ToBase64String(provider.WrapKey(key));
                    foreach (var algorithm in item.Algorithms)
                    {
                        theoryData.Add(new KeyWrapProviderTestData
                        {
                            SecurityKey = new X509SecurityKey(certificate),
                            Algorithm = algorithm,
                            PlainText = plainText,
                            Wrapped = wrapped,
                            Unwrap = true,
                            Wrap = true
                        });
                        theoryData.Add(new KeyWrapProviderTestData
                        {
                            SecurityKey = new RsaSecurityKey(privateKey),
                            Algorithm = algorithm,
                            PlainText = plainText,
                            Wrapped = wrapped,
                            Unwrap = true,
                            Wrap = true
                        });
                        theoryData.Add(new KeyWrapProviderTestData
                        {
                            SecurityKey = new RsaSecurityKey(privateKeyParameters),
                            Algorithm = algorithm,
                            PlainText = plainText,
                            Wrapped = wrapped,
                            Unwrap = true,
                            Wrap = true
                        });
                        theoryData.Add(new KeyWrapProviderTestData
                        {
                            SecurityKey = new RsaSecurityKey(publicKey),
                            Algorithm = algorithm,
                            PlainText = plainText,
                            Wrapped = wrapped,
                            Unwrap = false,
                            Wrap = true
                        });
                        theoryData.Add(new KeyWrapProviderTestData
                        {
                            SecurityKey = new RsaSecurityKey(publicKeyParamters),
                            Algorithm = algorithm,
                            PlainText = plainText,
                            Wrapped = wrapped,
                            Unwrap = false,
                            Wrap = true
                        });
                    }
                }
                return theoryData;
            }
        }

        class KeyWrapData
        {
            public string[] Algorithms { get; set; }
            public Func<SecurityKey, KeyWrapProvider> CreateProvider { get; set; }
        }


        public static TheoryData<SignatureProviderTestData> SignatureProviderTestData
        {
            get
            {
                var certificate = new X509Certificate2(Convert.FromBase64String(CertificateBase64), null as string, X509KeyStorageFlags.Exportable);
                var privateKey = certificate.GetRSAPrivateKey();
                var publicKey = certificate.GetRSAPublicKey();
                var privateKeyParameters = privateKey.ExportParameters(true);
                var publicKeyParamters = publicKey.ExportParameters(false);
                var plaintext = "Test data";
                var asymmetric = new[]
                {
                    new AsymmetricSignatureData
                    {
                        Data = plaintext,
                        Algorithms = new []
                        {
                            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                            "RS1"
                        },
                        HashAlgorithm = HashAlgorithmName.SHA1,
                        Padding = RSASignaturePadding.Pkcs1
                    },
                    new AsymmetricSignatureData
                    {
                        Data = plaintext,
                        Algorithms = new []
                        {
                            SecurityAlgorithms.RsaSha256,
                            SecurityAlgorithms.RsaSha256Signature
                        },
                        HashAlgorithm = HashAlgorithmName.SHA256,
                        Padding = RSASignaturePadding.Pkcs1
                    },
                    new AsymmetricSignatureData
                    {
                        Data = plaintext,
                        Algorithms = new []
                        {
                            SecurityAlgorithms.RsaSha384,
                            SecurityAlgorithms.RsaSha384Signature
                        },
                        HashAlgorithm = HashAlgorithmName.SHA384,
                        Padding = RSASignaturePadding.Pkcs1
                    },
                    new AsymmetricSignatureData
                    {
                        Data = plaintext,
                        Algorithms = new []
                        {
                            SecurityAlgorithms.RsaSha512,
                            SecurityAlgorithms.RsaSha512Signature
                        },
                        HashAlgorithm = HashAlgorithmName.SHA512,
                        Padding = RSASignaturePadding.Pkcs1
                    }
                };

                var theoryData = new TheoryData<SignatureProviderTestData>();
                foreach(var data in asymmetric)
                {
                    var signed = Convert.ToBase64String(privateKey.SignData(Encoding.UTF8.GetBytes(data.Data), data.HashAlgorithm, data.Padding));
                    foreach(var algorithm in data.Algorithms)
                    {
                        theoryData.Add(new SignatureProviderTestData
                        {
                            SigningKey = new X509SecurityKey(certificate),
                            Algorithm = algorithm,
                            Verify = true,
                            Sign = true,
                            Data = data.Data,
                            SignedData = signed
                        });
                        theoryData.Add(new SignatureProviderTestData
                        {
                            SigningKey = new RsaSecurityKey(privateKey),
                            Algorithm = algorithm,
                            Sign = true,
                            Data = data.Data,
                            SignedData = signed
                        });
                        theoryData.Add(new SignatureProviderTestData
                        {
                            SigningKey = new RsaSecurityKey(publicKey),
                            Algorithm = algorithm,
                            Verify = true,
                            Data = data.Data,
                            SignedData = signed
                        });
                        theoryData.Add(new SignatureProviderTestData
                        {
                            SigningKey = new RsaSecurityKey(privateKeyParameters),
                            Algorithm = algorithm,
                            Sign = true,
                            Data = data.Data,
                            SignedData = signed
                        });
                        theoryData.Add(new SignatureProviderTestData
                        {
                            SigningKey = new RsaSecurityKey(publicKeyParamters),
                            Algorithm = algorithm,
                            Verify = true,
                            Data = data.Data,
                            SignedData = signed
                        });
                    }
                }

                return theoryData;
            }
        }
        
        class AsymmetricSignatureData
        {
            public string Data { get; set; }
            public HashAlgorithmName HashAlgorithm { get; set; }
            public RSASignaturePadding Padding { get; set; }
            public string[] Algorithms { get; set; }
        }

        private CryptoProviderFactory CreateCryptoProviderFactory()
        {
            var services = new ServiceCollection()
                .AddCustomCryptoProvider()
                .BuildServiceProvider()
            ;

            return services.GetService<CryptoProviderFactory>();
        }
    }
}

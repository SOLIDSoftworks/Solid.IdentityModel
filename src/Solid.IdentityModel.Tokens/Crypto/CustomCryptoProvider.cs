using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using System.Linq;

namespace Solid.IdentityModel.Tokens.Crypto
{
    class CustomCryptoProvider : ICryptoProvider, IDisposable
    {
        private Lazy<CryptoProviderFactory> _lazyCryptoProviderFactory;

        private CryptoOptions _options;
        private IDisposable _optionsChangeToken;
        private ILogger<CustomCryptoProvider> _logger;
        private IServiceProvider _services;

        public CustomCryptoProvider(IOptionsMonitor<CryptoOptions> monitor, ILogger<CustomCryptoProvider> logger, IServiceProvider services)
        {
            _options = monitor.CurrentValue;
            _optionsChangeToken = monitor.OnChange((options, _) => _options = options);
            _logger = logger;
            _services = services;
            _lazyCryptoProviderFactory = new Lazy<CryptoProviderFactory>(() => _services.GetService<CryptoProviderFactory>(), System.Threading.LazyThreadSafetyMode.ExecutionAndPublication);
        }

        private CryptoProviderFactory CryptoProviderFactory => _lazyCryptoProviderFactory.Value;

        public object Create(string algorithm, params object[] args)
        {
            var type = AlgorithmType.Any;
            _logger.LogDebug($"Attempting to create crypto provider for '{algorithm}'.");

            if (_options.HashAlgorithmMap.TryGetValue(algorithm, out var mappedHashAlgorithm))
            {
                _logger.LogDebug($"Algorithm '{algorithm}' maps to hash algorithm '{mappedHashAlgorithm}'");
                type = AlgorithmType.Hash;
                algorithm = mappedHashAlgorithm;
            }
            if (_options.SignatureAlgorithmMap.TryGetValue(algorithm, out var mappedSignatureAlgorithm))
            {
                _logger.LogDebug($"Algorithm '{algorithm}' maps to signature algorithm '{mappedSignatureAlgorithm}'");
                type = AlgorithmType.Signature;
                algorithm = mappedSignatureAlgorithm;
            }
            if (_options.KeyWrapAlgorithmMap.TryGetValue(algorithm, out var mappedKeyWrapAlgorithm))
            {
                _logger.LogDebug($"Algorithm '{algorithm}' maps to key wrap algorithm '{mappedKeyWrapAlgorithm}'");
                type = AlgorithmType.KeyWrap;
                algorithm = mappedKeyWrapAlgorithm;
            }
            if (_options.KeyedHashAlgorithmMap.TryGetValue(algorithm, out var mappedKeyedashAlgorithm))
            {
                _logger.LogDebug($"Algorithm '{algorithm}' maps to keyed hash algorithm '{mappedKeyedashAlgorithm}'");
                type = AlgorithmType.KeyedHash;
                algorithm = mappedKeyedashAlgorithm;
            }
            if (_options.EncryptionAlgorithmMap.TryGetValue(algorithm, out var mappedEncryptionAlgorithm))
            {
                _logger.LogDebug($"Algorithm '{algorithm}' maps to encryption algorithm '{mappedEncryptionAlgorithm}'");
                type = AlgorithmType.Encryption;
                algorithm = mappedEncryptionAlgorithm;
            }

            if (type.HasFlag(AlgorithmType.Hash))
            {
                if (_options.SupportedHashAlgorithms.TryGetValue(algorithm, out var hashAlgorithmDescriptor))
                {
                    _logger.LogDebug($"Creating {nameof(HashAlgorithm)} for '{algorithm}'");
                    return hashAlgorithmDescriptor.Factory(_services, args);
                }
                if(type == AlgorithmType.Hash)
                    return CryptoProviderFactory.CreateHashAlgorithm(algorithm);
            }

            if (type.HasFlag(AlgorithmType.Signature))
            {
                if (_options.SupportedSignatureAlgorithms.TryGetValue(algorithm, out var signatureProviderDescriptor))
                {
                    _logger.LogDebug($"Creating {nameof(SignatureProvider)} for '{algorithm}'");
                    return signatureProviderDescriptor.Factory(_services, args);
                }
                if (type == AlgorithmType.Signature)
                {
                    if (args.ElementAtOrDefault(1) is bool willCreate)
                    {
                        if (willCreate)
                            return CryptoProviderFactory.CreateForSigning(args.ElementAtOrDefault(0) as SecurityKey, algorithm);
                        else
                            return CryptoProviderFactory.CreateForVerifying(args.ElementAtOrDefault(0) as SecurityKey, algorithm);
                    }
                }
            }

            if (type.HasFlag(AlgorithmType.KeyedHash))
            {
                if (_options.SupportedKeyedHashAlgorithms.TryGetValue(algorithm, out var keyedHashAlgorithmDescriptor))
                {
                    _logger.LogDebug($"Creating {nameof(KeyedHashAlgorithm)} for '{algorithm}'");
                    return keyedHashAlgorithmDescriptor.Factory(_services, args);
                }
                if (type == AlgorithmType.KeyedHash)
                    return CryptoProviderFactory.CreateKeyedHashAlgorithm(args.ElementAtOrDefault(0) as byte[], algorithm);
            }

            if (type.HasFlag(AlgorithmType.KeyWrap))
            {
                if (_options.SupportedKeyWrapAlgorithms.TryGetValue(algorithm, out var keyWrapProviderDescriptor))
                {
                    _logger.LogDebug($"Creating {nameof(KeyWrapProvider)} for '{algorithm}'");
                    return keyWrapProviderDescriptor.Factory(_services, args);
                }
                if (type == AlgorithmType.KeyWrap)
                {
                    if (args.ElementAtOrDefault(1) is bool willUnwrap && willUnwrap)
                        return CryptoProviderFactory.CreateKeyWrapProviderForUnwrap(args.ElementAtOrDefault(0) as SecurityKey, algorithm);
                    return CryptoProviderFactory.CreateKeyWrapProvider(args.ElementAtOrDefault(0) as SecurityKey, algorithm);
                }
            }

            if (type.HasFlag(AlgorithmType.Encryption))
            {
                if (_options.SupportedEncryptionAlgorithms.TryGetValue(algorithm, out var authenticatedEncryptionProviderDescriptor))
                {
                    _logger.LogDebug($"Creating {nameof(AuthenticatedEncryptionProvider)} for '{algorithm}'");
                    return authenticatedEncryptionProviderDescriptor.Factory(_services, args);
                }
                if(type == AlgorithmType.Encryption)
                    return CryptoProviderFactory.CreateAuthenticatedEncryptionProvider(args.ElementAtOrDefault(0) as SecurityKey, algorithm);
            }

            if (type.HasFlag(AlgorithmType.Symmetric))
            {
                if (_options.SupportedSymmetricAlgorithms.TryGetValue(algorithm, out var symmetricAlgorithmDescriptor))
                {
                    _logger.LogDebug($"Creating {nameof(SymmetricAlgorithm)} for '{algorithm}'");
                    return symmetricAlgorithmDescriptor.Factory(_services, args);
                }
                // default crypto provider factory does not support symmetric algorithms only
            }

            throw new NotSupportedException(algorithm);
        }

        public bool IsSupportedAlgorithm(string algorithm, params object[] args)
        {
            return
                IsSupportedAlgorithm(_options.HashAlgorithmMap, algorithm, args) ||
                IsSupportedAlgorithm(_options.SignatureAlgorithmMap, algorithm, args) ||
                IsSupportedAlgorithm(_options.KeyedHashAlgorithmMap, algorithm, args) ||
                IsSupportedAlgorithm(_options.KeyWrapAlgorithmMap, algorithm, args) ||
                IsSupportedAlgorithm(_options.EncryptionAlgorithmMap, algorithm, args) ||
                IsSupportedByCustomCryptoProvider(algorithm)
            ;
        }

        private bool IsSupportedAlgorithm(IDictionary<string, string> map, string algorithm, object[] args)
        {
            if (map.TryGetValue(algorithm, out var mapped))
            {
                if (args.ElementAtOrDefault(0) is SecurityKey key)
                    return CryptoProviderFactory.IsSupportedAlgorithm(mapped, key);
                else
                    return CryptoProviderFactory.IsSupportedAlgorithm(mapped);
            }
            return false;
        }

        public void Release(object cryptoInstance)
        {
            if (cryptoInstance is IDisposable disposable)
                disposable.Dispose();
        }

        public void Dispose() => _optionsChangeToken?.Dispose();

        private bool IsSupportedByCustomCryptoProvider(string algorithm)
        {
            return
                _options.SupportedSymmetricAlgorithms.ContainsKey(algorithm) ||
                _options.SupportedHashAlgorithms.ContainsKey(algorithm) ||
                _options.SupportedSignatureAlgorithms.ContainsKey(algorithm) ||
                _options.SupportedEncryptionAlgorithms.ContainsKey(algorithm) ||
                _options.SupportedKeyedHashAlgorithms.ContainsKey(algorithm) ||
                _options.SupportedKeyWrapAlgorithms.ContainsKey(algorithm)
            ;
        }

        enum AlgorithmType
        {
            Hash = 1,
            Signature = 2,
            KeyedHash = 4, 
            KeyWrap = 8,
            Encryption = 16,
            Symmetric = 32,
            Any = Hash | Signature | KeyedHash | KeyWrap | Encryption | Symmetric
        }
    }
}

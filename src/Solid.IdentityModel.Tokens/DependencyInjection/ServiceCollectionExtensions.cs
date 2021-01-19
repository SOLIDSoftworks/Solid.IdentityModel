using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Solid.IdentityModel.Tokens;
using Solid.IdentityModel.Tokens.Crypto;
using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class Solid_IdentityModel_Tokens_ServiceCollectionExtensions
    {
        public static IServiceCollection AddCustomCryptoProvider(this IServiceCollection services) => services.AddCustomCryptoProvider(options => options.AddFullSupport());
        public static IServiceCollection AddCustomCryptoProvider(this IServiceCollection services, Action<CryptoOptions> configureOptions)
        {
            services.Configure(configureOptions);
            services.AddLogging();
            services.TryAddSingleton<CustomCryptoProvider>();
            services.TryAddSingleton<CryptoProviderFactory>(p =>
            {
                var options = p.GetRequiredService<IOptions<CryptoOptions>>().Value;
                var custom = p.GetRequiredService<CustomCryptoProvider>();

                var factory = null as CryptoProviderFactory;
                if (options.UseDefaultCryptoProviderFactory)
                    factory = CryptoProviderFactory.Default;
                else
                    factory = new CryptoProviderFactory();

                factory.CustomCryptoProvider = p.GetRequiredService<CustomCryptoProvider>();
                return factory;
            });
            return services;
        }
    }
}

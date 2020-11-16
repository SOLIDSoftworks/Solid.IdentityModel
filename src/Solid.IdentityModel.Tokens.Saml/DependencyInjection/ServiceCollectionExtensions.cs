using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens.Saml2;
using Solid.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.IdentityModel.Tokens.DependencyInjection
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddSaml2EncryptedSecurityTokenHandler(this IServiceCollection services)
            => services.AddSaml2EncryptedSecurityTokenHandler<Saml2EncryptedSecurityTokenHandler>();

        public static IServiceCollection AddSaml2EncryptedSecurityTokenHandler<THandler>(this IServiceCollection services)
            where THandler : Saml2EncryptedSecurityTokenHandler
        {
            services.TryAddTransient<Saml2SecurityTokenHandler, THandler>();
            return services;
        }

        public static IServiceCollection AddExtendedSaml2Serializer<TSerializer>(this IServiceCollection services)
            where TSerializer : ExtendedSaml2Serializer
        {
            services.TryAddTransient<Saml2Serializer, TSerializer>();
            return services;
        }
    }
}

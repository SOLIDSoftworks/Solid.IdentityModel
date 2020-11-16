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
        public static IServiceCollection AddSaml2Encryption(this IServiceCollection services)
        {
            services.TryAddTransient<Saml2SecurityTokenHandler, Saml2EncryptedSecurityTokenHandler>();
            services.TryAddTransient<Saml2Serializer, ExtendedSaml2Serializer>();
            return services;
        }
    }
}

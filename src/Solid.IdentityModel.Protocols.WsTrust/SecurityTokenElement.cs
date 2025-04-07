using System;
using Solid.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Logging;

namespace Solid.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// The <see cref="SecurityTokenElement"/> is used to represent a <see cref="SecurityToken"/> to provide serialization for key material and security tokens.
    /// </summary>
    public class SecurityTokenElement
    {
        /// <summary>
        /// Creates an instance of <see cref="SecurityTokenElement"/>.
        /// </summary>
        /// <param name="securityToken">The <see cref="SecurityToken"/>that will be serialized.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="securityToken"/> is null.</exception>
        public SecurityTokenElement(SecurityToken securityToken)
        {
            SecurityToken = securityToken ?? throw LogHelper.LogArgumentNullException(nameof(securityToken));
        }

        /// <summary>
        /// Creates an instance of <see cref="SecurityTokenElement"/>.
        /// </summary>
        /// <param name="securityTokenReference">the <see cref="SecurityTokenReference"/> that will be serialized.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="securityTokenReference"/> is null.</exception>
        public SecurityTokenElement(SecurityTokenReference securityTokenReference)
        {
            SecurityTokenReference = securityTokenReference ?? throw LogHelper.LogArgumentNullException(nameof(securityTokenReference));
        }

        /// <summary>
        /// Gets the <see cref="SecurityToken"/>.
        /// </summary>
        public SecurityToken SecurityToken { get; }

        /// <summary>
        /// Gets the <see cref="SecurityTokenReference"/>.
        /// </summary>
        public SecurityTokenReference SecurityTokenReference { get; }
    }
}

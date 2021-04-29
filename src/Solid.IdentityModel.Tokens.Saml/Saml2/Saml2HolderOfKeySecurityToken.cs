using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.IdentityModel.Tokens.Saml2
{
    internal class Saml2HolderOfKeySecurityToken : Saml2SecurityToken
    {
        public Saml2HolderOfKeySecurityToken(Saml2Assertion assertion, SecurityKey proofKey)
            : base(assertion)
        {
            SecurityKey = proofKey;
        }

        public override SecurityKey SecurityKey { get; }
    }
}

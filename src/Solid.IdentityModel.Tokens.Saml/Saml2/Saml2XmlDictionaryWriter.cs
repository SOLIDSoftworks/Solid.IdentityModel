using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;

namespace Solid.IdentityModel.Tokens.Saml2
{
    internal class Saml2XmlDictionaryWriter : DelegatingXmlDictionaryWriter
    {
        private readonly string[] _saml2Types = new[]
        {
            Saml2Constants.Types.KeyInfoConfirmationDataType
        };

        public Saml2XmlDictionaryWriter(XmlWriter inner)
        {
            InnerWriter = CreateDictionaryWriter(inner);
        }

        public override void WriteString(string text)
        {
            if (_saml2Types.Contains(text))
                text = $"{Saml2Constants.Prefix}:{text}";
            base.WriteString(text);
        }
    }
}

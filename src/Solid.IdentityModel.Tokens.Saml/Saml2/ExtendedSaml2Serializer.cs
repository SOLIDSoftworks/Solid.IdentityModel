using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;

namespace Solid.IdentityModel.Tokens.Saml2
{
    public class ExtendedSaml2Serializer : Saml2Serializer
    {
        public override void WriteAttribute(XmlWriter writer, Saml2Attribute attribute)
        {
            if (string.IsNullOrEmpty(attribute.AttributeValueXsiType))
            {
                base.WriteAttribute(writer, attribute);
                return;
            }

            var dictionaryWriter = null as XmlDictionaryWriter;
            if (writer is XmlDictionaryWriter w)
                dictionaryWriter = w;
            else
                dictionaryWriter = XmlDictionaryWriter.CreateDictionaryWriter(writer);
            var xsi = "http://www.w3.org/2001/XMLSchema-instance";
            dictionaryWriter.WriteStartElement(Saml2Constants.Elements.Attribute, Saml2Constants.Namespace);
            dictionaryWriter.WriteAttributeString(Saml2Constants.Attributes.Name, attribute.Name);
            dictionaryWriter.WriteAttributeString(Saml2Constants.Attributes.NameFormat, attribute.NameFormat?.ToString() ?? Saml2Constants.NameIdentifierFormats.UnspecifiedString);
            foreach (var value in attribute.Values)
            {
                dictionaryWriter.WriteStartElement(Saml2Constants.Elements.AttributeValue, Saml2Constants.Namespace);

                var fqtn = attribute.AttributeValueXsiType?.Split('#');
                if (fqtn?.Length == 2)
                {
                    dictionaryWriter.WriteAttributeString("xmlns", "xs", null, fqtn[0]);
                    //dictionaryWriter.WriteXmlnsAttribute("xs", fqtn[0]);
                    dictionaryWriter.WriteStartAttribute("xsi", "type", xsi);
                    dictionaryWriter.WriteQualifiedName(fqtn[1], fqtn[0]);
                    dictionaryWriter.WriteEndAttribute();
                }

                dictionaryWriter.WriteString(value);
                dictionaryWriter.WriteEndElement();
            }
            dictionaryWriter.WriteEndElement();
        }
    }
}

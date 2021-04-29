using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using Solid.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;

namespace Solid.IdentityModel.Tokens.Saml2
{
    public class ExtendedSaml2Serializer : Saml2Serializer
    {
        public ExtendedSaml2Serializer()
            : this(new ExtendedDSigSerializer())
        {

        }

        public ExtendedSaml2Serializer(ExtendedDSigSerializer dsigSerializer)
        {
            DSigSerializer = dsigSerializer;
        }

        protected override Saml2SubjectConfirmation ReadSubjectConfirmation(XmlDictionaryReader reader)
        {
            return base.ReadSubjectConfirmation(reader);
        }
        protected override Saml2SubjectConfirmationData ReadSubjectConfirmationData(XmlDictionaryReader reader)
        {
            var type = XmlUtil.GetXsiTypeAsQualifiedName(reader);
            var p = XmlUtil.EqualsQName(type, Saml2Constants.Types.KeyInfoConfirmationDataType, XmlSignatureConstants.XmlSchemaNamespace);
            return base.ReadSubjectConfirmationData(reader);
        }

        protected override void WriteSubjectConfirmationData(XmlWriter writer, Saml2SubjectConfirmationData subjectConfirmationData)
        {
            base.WriteSubjectConfirmationData(new Saml2XmlDictionaryWriter(writer), subjectConfirmationData);
        }

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
                    if (string.IsNullOrEmpty(dictionaryWriter.LookupPrefix("xs")))
                        dictionaryWriter.WriteAttributeString("xmlns", "xs", null, fqtn[0]);

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

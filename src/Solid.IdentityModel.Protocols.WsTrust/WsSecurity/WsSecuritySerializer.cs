using System.IO;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Solid.IdentityModel.Protocols.WsUtility;
using Microsoft.IdentityModel.Xml;

#pragma warning disable 1591

namespace Solid.IdentityModel.Protocols.WsSecurity
{
    /// <summary>
    /// Base class for support of serializing versions of WS-Security.
    /// see: https://www.oasis-open.org/committees/download.php/16790/wss-v1.1-spec-os-SOAPMessageSecurity.pdf (1.1)
    /// see: http://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-SOAPMessageSecurity-v1.1.1-os.html (1.1.1)
    /// </summary>
    public static class WsSecuritySerializer
    {
        /// <summary>
        /// Creates an <see cref="XmlElement"/> to wrap a <see cref="SecurityTokenReference"/>
        /// </summary>
        /// <param name="securityTokenReference"></param>
        /// <returns></returns>
        public static XmlElement CreateXmlElement(SecurityTokenReference securityTokenReference)
        {
            if (securityTokenReference == null)
                throw LogHelper.LogArgumentNullException(nameof(securityTokenReference));

            using (var stream = new MemoryStream())
            {
                using (var writer = XmlDictionaryWriter.CreateTextWriter(stream, Encoding.UTF8, false))
                {
                    WriteSecurityTokenReference(writer, securityTokenReference);
                    writer.Flush();
                    stream.Seek(0, SeekOrigin.Begin);
                    var dom = new XmlDocument
                    {
                        PreserveWhitespace = true
                    };

                    using (var textReader = new XmlTextReader(stream) { DtdProcessing = DtdProcessing.Prohibit })
                    {
                        dom.Load(textReader);
                        return dom.DocumentElement;
                    }
                }
            }
        }

        internal static SecurityTokenReference ReadSecurityTokenReference(XmlDictionaryReader reader)
        {
            //  <wsse:SecurityTokenReference wsu:Id="...",
            //                               wsse:TokenType="...",
            //                               wsse:Usage="...">
            //      ...
            //  </wsse:SecurityTokenReference>

            XmlAttributeHolder[] xmlAttributes = XmlAttributeHolder.ReadAttributes(reader);
            var securityTokenReference = new SecurityTokenReference
            {
                Id = XmlAttributeHolder.GetAttribute(xmlAttributes, WsUtilityAttributes.Id, WsSecurityConstants.WsSecurity10.Namespace),
                TokenType = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.TokenType, WsSecurityConstants.WsSecurity11.Namespace),
                Usage = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.Usage, WsSecurityConstants.WsSecurity10.Namespace)
            };

            bool isEmptyElement = reader.IsEmptyElement;
            reader.ReadStartElement();
            if (reader.IsStartElement() && reader.IsLocalName(WsSecurityElements.KeyIdentifier))
                securityTokenReference.KeyIdentifier = ReadKeyIdentifier(reader);

            if (!isEmptyElement)
                reader.ReadEndElement();

            return securityTokenReference;
        }

        internal static KeyIdentifier ReadKeyIdentifier(XmlDictionaryReader reader)
        {
            //  <wsse:KeyIdentifier wsu:Id="..."
            //                      ValueType="..."
            //                      EncodingType="...">
            //      ...
            //  </wsse:KeyIdentifier>

            bool isEmptyElement = reader.IsEmptyElement;
            var xmlAttributes = XmlAttributeHolder.ReadAttributes(reader);

            var keyIdentifier = new KeyIdentifier
            {
                Id = XmlAttributeHolder.GetAttribute(xmlAttributes, WsUtilityAttributes.Id, WsSecurityConstants.WsSecurity10.Namespace),
                EncodingType = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.EncodingType, WsSecurityConstants.WsSecurity10.Namespace),
                ValueType = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.ValueType, WsSecurityConstants.WsSecurity10.Namespace)
            };

            reader.ReadStartElement();
            if (!isEmptyElement)
            {
                keyIdentifier.Value = reader.ReadContentAsString();
                reader.ReadEndElement();
            }

            return keyIdentifier;
        }

        internal static void WriteKeyIdentifier(XmlDictionaryWriter writer, KeyIdentifier keyIdentifier)
        {
            //  <wsse:KeyIdentifier wsu:Id="..."
            //                      ValueType="..."
            //                      EncodingType="...">
            //      ...
            //  </wsse:KeyIdentifier>

            writer.WriteStartElement(WsSecurityConstants.WsSecurity10.Prefix, WsSecurityElements.KeyIdentifier, WsSecurityConstants.WsSecurity10.Namespace);

            if (!string.IsNullOrEmpty(keyIdentifier.Id))
                writer.WriteAttributeString(WsUtilityAttributes.Id, keyIdentifier.Id);

            if (!string.IsNullOrEmpty(keyIdentifier.ValueType))
                writer.WriteAttributeString(WsSecurityAttributes.ValueType, keyIdentifier.ValueType);

            if (!string.IsNullOrEmpty(keyIdentifier.EncodingType))
                writer.WriteAttributeString(WsSecurityAttributes.EncodingType, keyIdentifier.EncodingType);

            if (!string.IsNullOrEmpty(keyIdentifier.Value))
                writer.WriteString(keyIdentifier.Value);

            writer.WriteEndElement();
        }

        internal static void WriteSecurityTokenReference(XmlDictionaryWriter writer, SecurityTokenReference securityTokenReference)
        {
            // <wsse:SecurityTokenReference>
            //      <wsse:KeyIdentifier wsu:Id="..."
            //                          ValueType="..."
            //                          EncodingType="...">
            //          ...
            //      </wsse:KeyIdentifier>
            //  </wsse:SecurityTokenReference>

            writer.WriteStartElement(WsSecurityConstants.WsSecurity10.Prefix, WsSecurityElements.SecurityTokenReference, WsSecurityConstants.WsSecurity10.Namespace);

            // For Saml2 tokens, the 'TokenType' was defined in must be in wsse1.1 namespace
            if (!string.IsNullOrEmpty(securityTokenReference.TokenType))
                writer.WriteAttributeString(WsSecurityAttributes.TokenType, WsSecurityConstants.WsSecurity11.Namespace, securityTokenReference.TokenType);

            if (!string.IsNullOrEmpty(securityTokenReference.Id))
                writer.WriteAttributeString(WsUtilityAttributes.Id, securityTokenReference.Id);

            if (securityTokenReference.KeyIdentifier != null)
                WriteKeyIdentifier(writer, securityTokenReference.KeyIdentifier);

            writer.WriteEndElement();
        }
    }
}

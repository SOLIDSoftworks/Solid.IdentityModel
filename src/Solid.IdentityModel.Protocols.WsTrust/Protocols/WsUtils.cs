using System;
using System.IO;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Xml;

namespace Solid.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Utilities for working with WS-* 
    /// </summary>
    internal static class WsUtils
    {
        /// <summary>
        /// Assumes the xmlreader is positioned on a startelement.
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        internal static XmlElement ReadAsXmlElement(XmlDictionaryReader reader)
        {
            XmlElement xmlElement = null;
            using (var ms = new MemoryStream())
            {
                using (XmlWriter writer = XmlDictionaryWriter.CreateTextWriter(ms, Encoding.UTF8, false))
                {
                    writer.WriteNode(reader, true);
                    writer.Flush();
                }

                ms.Seek(0, SeekOrigin.Begin);
                if (ms.Length == 0)
                    return null;

                using (var memoryReader = XmlDictionaryReader.CreateTextReader(ms, Encoding.UTF8, XmlDictionaryReaderQuotas.Max, null))
                {
                    XmlDocument dom = new XmlDocument
                    {
                        PreserveWhitespace = true
                    };

                    dom.Load(memoryReader);
                    xmlElement = dom.DocumentElement;
                }
            }

            return xmlElement;
        }

        /// <summary>
        /// Helper method to read a element string
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        internal static string ReadStringElement(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (reader.IsEmptyElement)
            {
                reader.ReadStartElement();
                return null;
            }

            reader.ReadStartElement();
            var strVal = reader.ReadContentAsString();
            reader.MoveToContent();
            reader.ReadEndElement();

            return strVal;
        }

        /// <summary>
        /// Helper method to read an int element
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        internal static int? ReadIntElement(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (reader.IsEmptyElement)
            {
                reader.ReadStartElement();
                return null;
            }

            reader.ReadStartElement();
            var intVal = reader.ReadContentAsInt();
            reader.MoveToContent();
            reader.ReadEndElement();

            return intVal;
        }

        /// <summary>
        /// Checks standard items on a write call.
        /// </summary>
        internal static void ValidateParamsForWritting(XmlWriter writer, WsSerializationContext serializationContext, object obj, string objName)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (serializationContext == null)
                throw LogHelper.LogArgumentNullException(nameof(serializationContext));

            if (obj == null)
                throw LogHelper.LogArgumentNullException(objName);
        }

        /// <summary>
        /// Checks if the <see cref="XmlReader"/> is pointing to an expected element.
        /// </summary>
        /// <param name="reader">the <see cref="XmlReader"/>to check.</param>
        /// <param name="element">the expected element.</param>
        /// <param name="serializationContext">the expected namespace.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="reader"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="element"/> is null or empty.</exception>
        /// <exception cref="XmlReadException">if <paramref name="reader"/> if not at a StartElement.</exception>
        /// <exception cref="XmlReadException">if <paramref name="reader"/> if not at expected element.</exception>
        internal static void CheckReaderOnEntry(XmlReader reader, string element, WsSerializationContext serializationContext)
        {
            if (serializationContext == null)
                throw LogHelper.LogArgumentNullException(nameof(serializationContext));

            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            // IsStartElement calls reader.MoveToContent().
            if (!reader.IsStartElement())
                throw XmlUtil.LogReadException(LogMessages.IDX15022, reader.NodeType);

            if (!reader.IsStartElement(element, serializationContext.TrustConstants.Namespace))
                throw XmlUtil.LogReadException(LogMessages.IDX15011, serializationContext.TrustConstants.Namespace, element, reader.NamespaceURI, reader.LocalName);
        }
    }
}

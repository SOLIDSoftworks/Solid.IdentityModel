using Microsoft.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace System.Xml
{
    public static class XmlReaderExtensions
    {
        public static void ForEachChild(this XmlReader reader, Action<XmlReader> action)
        {
            if(!reader.IsEmptyElement && reader.Read())
            {
                while (reader.IsStartElement())
                {
                    using (var child = reader.ReadElement())
                        action(child);
                }
            }
        }

        public static XmlReader ReadElement(this XmlReader reader)
        {
            if (!reader.IsStartElement())
                throw new InvalidOperationException("Cannot get reader for element if original reader isn't placed on element.");
            
            var stream = new MemoryStream();
            using (var writer = XmlWriter.Create(stream, new XmlWriterSettings { CloseOutput = false, OmitXmlDeclaration = true }))
                writer.WriteNode(reader, true);

            stream.Position = 0;
            var child = XmlReader.Create(stream, reader.Settings);
            child.MoveToContent();
            return child;
        }
    }
}

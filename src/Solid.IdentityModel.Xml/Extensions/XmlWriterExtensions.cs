﻿using System;
using System.Collections.Generic;
using System.Text;

namespace System.Xml
{
    public static class XmlWriterExtensions
    {
        public static bool TryWriteAttributeValue(this XmlWriter writer, string localName, ushort? value)
        {
            if (value == null) return false;
            writer.WriteAttributeString(localName, value.Value.ToString());
            return true;
        }
        public static bool TryWriteAttributeValue(this XmlWriter writer, string localName, DateTime? value)
        {
            if (value == null) return false;
            writer.WriteAttributeString(localName, XmlConvert.ToString(value.Value, XmlDateTimeSerializationMode.Utc));
            return true;
        }

        public static bool TryWriteAttributeValue(this XmlWriter writer, string localName, TimeSpan? value)
        {
            if (value == null) return false;
            writer.WriteAttributeString(localName, XmlConvert.ToString(value.Value));
            return true;
        }

        public static bool TryWriteAttributeValue(this XmlWriter writer, string localName, bool? value)
        {
            if (value == null) return false;
            writer.WriteAttributeString(localName, value.Value.ToString().ToLower());
            return true;
        }

        public static bool TryWriteAttributeValue(this XmlWriter writer, string localName, Uri value)
        {
            if (value == null) return false;
            writer.WriteAttributeString(localName, value.OriginalString);
            return true;
        }

        public static bool TryWriteAttributeValue(this XmlWriter writer, string localName, string value, bool allowEmpty = false)
        {
            if (value == null) return false;
            if (!allowEmpty && string.IsNullOrEmpty(value)) return false;
            writer.WriteAttributeString(localName, value);
            return true;
        }

        public static bool TryWriteValue(this XmlWriter writer, Uri value)
        {
            if (value == null) return false;
            writer.WriteValue(value.OriginalString);
            return true;
        }

        public static bool TryWriteValue(this XmlWriter writer, string value, bool allowEmpty = false)
        {
            if (value == null) return false;
            if (!allowEmpty && string.IsNullOrEmpty(value)) return false;
            writer.WriteValue(value);
            return true;
        }

        public static bool TryWriteElementValue(this XmlWriter writer, string localName, string ns, string value, bool allowEmpty = false)
        {
            if (value == null) return false;
            if (!allowEmpty && string.IsNullOrEmpty(value)) return false;
            writer.WriteElementString(localName, ns, value);
            return true;
        }

        public static bool TryWriteElementValue(this XmlWriter writer, string localName, string ns, Uri value, bool allowEmpty = false)
        {
            var original = value?.OriginalString;
            if (!allowEmpty && string.IsNullOrEmpty(original)) return false;
            writer.WriteElementString(localName, ns, original ?? string.Empty);
            return true;
        }
    }
}

﻿using System;
using Microsoft.IdentityModel.Logging;
using Solid.IdentityModel.Protocols.WsSecurity;

namespace Solid.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of the BinaryExchange element.
    /// see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html
    /// </summary>
    internal class BinaryExchange
    {
        private byte[] _binaryData;

        /// <summary>
        /// Creates an instance of <see cref="BinaryExchange"/>
        /// </summary>
        /// <param name="binaryData">Binary data exchanged.</param>
        /// <param name="valueType">Uri representing the value type of the binary data.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="binaryData"/> or <paramref name="valueType"/>.</exception>
        /// <remarks>Default encoding type is: "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1/#Base64Binary".
        /// for possible values see: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html#wssecurity".</remarks>
        public BinaryExchange( byte[] binaryData, Uri valueType )
            : this( binaryData, valueType, new Uri( WsSecurityEncodingTypes.WsSecurity11.Base64 ) )
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="BinaryExchange"/>
        /// </summary>
        /// <param name="binaryData">Binary data exchanged.</param>
        /// <param name="valueType">Uri representing the value type of the binary data.</param>
        /// <param name="encodingType">Encoding type to be used for encoding teh </param>
        /// <exception cref="ArgumentNullException">if <paramref name="binaryData"/>, <paramref name="valueType"/> or <paramref name="encodingType"/> is null.</exception>
        public BinaryExchange( byte[] binaryData, Uri valueType, Uri encodingType )
        {
            BinaryData = binaryData ?? throw LogHelper.LogArgumentNullException(nameof(binaryData));
            ValueType = valueType ?? throw LogHelper.LogArgumentNullException(nameof(valueType)); ;
            EncodingType = encodingType ?? throw LogHelper.LogArgumentNullException(nameof(encodingType)); ;
        }

        /// <summary>
        /// Gets the Binary Data.
        /// </summary>
        public byte[] BinaryData
        {
            get
            {
                byte[] binaryCopy = new byte[_binaryData.Length];
                Array.Copy(_binaryData, binaryCopy, _binaryData.Length);
                return binaryCopy;
            }

            private set
            {
                _binaryData = value;
            }
        }

        /// <summary>
        /// Gets the ValueType Uri.
        /// </summary>
        public Uri ValueType { get; }

        /// <summary>
        /// Gets the EncodingType Uri.
        /// </summary>
        public Uri EncodingType { get; }
    }
}

namespace Solid.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Values for BinarySecrectTypes for WsTrust Feb2005, 1.3 and 1.4.
    /// </summary>
    public abstract class WsTrustBinarySecretTypes
    {
        /// <summary>
        /// Gets the an instance of WsTrust Feb2005 BinarySecretTypes.
        /// <para>see: http://specs.xmlsoap.org/ws/2005/02/trust/WS-Trust.pdf </para>
        /// </summary>
        public static WsTrustFeb2005BinarySecretTypes TrustFeb2005 { get; } = new WsTrustFeb2005BinarySecretTypes();

        /// <summary>
        /// Gets the an instance of WsTrust 1.3 BinarySecretTypes.
        /// <para>see: http://specs.xmlsoap.org/ws/2005/02/trust/WS-Trust.pdf </para>
        /// </summary>
        public static WsTrust13BinarySecretTypes Trust13 { get; } = new WsTrust13BinarySecretTypes();

        /// <summary>
        /// Gets the an instance of WsTrust 1.4 BinarySecretTypes.
        /// <para>see: http://specs.xmlsoap.org/ws/2005/02/trust/WS-Trust.pdf </para>
        /// </summary>
        public static WsTrust14BinarySecretTypes Trust14 { get; } = new WsTrust14BinarySecretTypes();

        /// <summary>
        /// Gets the AsymmetricKey value.
        /// </summary>
        public string AsymmetricKey { get; protected set; }

        /// <summary>
        /// Gets the Nonce value.
        /// </summary>
        public string Nonce { get; protected set; }

        /// <summary>
        /// Gets the Symmetric value.
        /// </summary>
        public string SymmetricKey { get; protected set; }
    }

    /// <summary>
    /// Values for BinarySecretTypes for WsTrust Feb2005.
    /// </summary>
    public class WsTrustFeb2005BinarySecretTypes : WsTrustBinarySecretTypes
    {
        /// <summary>
        /// Creates an instance of <see cref="WsTrustFeb2005BinarySecretTypes"/>.
        /// <para>The property <see cref="WsTrustBinarySecretTypes.TrustFeb2005"/>  maintains a singleton instance of BinarySecretTypes for WsTrust Feb2005.</para>
        /// </summary>
        public WsTrustFeb2005BinarySecretTypes()
        {
            AsymmetricKey = "http://schemas.xmlsoap.org/ws/2005/02/trust/AsymmetricKey";
            Nonce = "http://schemas.xmlsoap.org/ws/2005/02/trust/Nonce";
            SymmetricKey = "http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey";
        }
    }

    /// <summary>
    /// Values for BinarySecretTypes for WsTrust 1.3.
    /// </summary>
    public class WsTrust13BinarySecretTypes : WsTrustBinarySecretTypes
    {
        /// <summary>
        /// Creates an instance of <see cref="WsTrust13BinarySecretTypes"/>.
        /// <para>The property <see cref="WsTrustBinarySecretTypes.TrustFeb2005"/>  maintains a singleton instance of BinarySecretTypes for WsTrust 1.3.</para>
        /// </summary>
        public WsTrust13BinarySecretTypes()
        {
            AsymmetricKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/AsymmetricKey";
            Nonce = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Nonce";
            SymmetricKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey"; ;
        }
    }

    /// <summary>
    /// Values for BinarySecretTypes for WsTrust 1.4.
    /// </summary>
    public class WsTrust14BinarySecretTypes : WsTrustBinarySecretTypes
    {
        /// <summary>
        /// Creates an instance of <see cref="WsTrust14BinarySecretTypes"/>.
        /// <para>The property <see cref="WsTrustBinarySecretTypes.Trust14"/>  maintains a singleton instance of BinarySecretTypes for WsTrust 1.4.</para>
        /// </summary>
        public WsTrust14BinarySecretTypes()
        {
            AsymmetricKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer";
            Nonce = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Nonce";
            SymmetricKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey";
        }
    }
}

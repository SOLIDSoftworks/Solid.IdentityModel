using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using Solid.IdentityModel.FederationMetadata.WsAddressing;
using Solid.IdentityModel.FederationMetadata.WsAuthorization;
using Solid.IdentityModel.Tokens.Saml2.Metadata;
using Solid.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using static Solid.IdentityModel.FederationMetadata.WsFederationConstants;

namespace Solid.IdentityModel.FederationMetadata
{
    public class FederationMetadataSerializer : Saml2MetadataSerializer
    {
        protected WsAuthorizationSerializer WsAuthorizationSerializer { get; }
        protected WsAddressingSerializer WsAddressingSerializer { get; }

        public FederationMetadataSerializer()
            : this(new WsAuthorizationSerializer(), new WsAddressingSerializer(), new Saml2Serializer(), new DSigSerializer())
        {
        }

        public FederationMetadataSerializer(WsAuthorizationSerializer wsAuthorizationSerializer, WsAddressingSerializer wsAddressingSerializer, Saml2Serializer saml2Serializer, DSigSerializer dSigSerializer) 
            : base(saml2Serializer, dSigSerializer)
        {
            WsAuthorizationSerializer = wsAuthorizationSerializer;
            WsAddressingSerializer = wsAddressingSerializer;
        }

        protected override bool TryReadRoleDescriptor(XmlDictionaryReader reader, out RoleDescriptor role)
        {
            if (!reader.IsStartElement(Saml2MetadataConstants.Elements.RoleDescriptor, Saml2MetadataConstants.Namespace))
                return Out.False(out role);

            var d = null as RoleDescriptor;
            if(reader.TryReadFederationEndpointType(out var type))
            {
                if (type == FederationEndpointType.ApplicationService)
                    d = new ApplicationServiceDescriptor();
                if (type == FederationEndpointType.AttributeService)
                    d = new AttributeServiceDescriptor();
                if (type == FederationEndpointType.PseudonymService)
                    d = new PseudonymServiceDescriptor();
                if (type == FederationEndpointType.SecurityTokenService)
                    d = new SecurityTokenServiceDescriptor();
            }
            if(d == null)
                d = new RoleDescriptor();
            ReadRoleDescriptorAttributes(reader, d);

            reader.ForEachChild(r => TryReadRoleDescriptorChild(r, d), out var signature);
            d.Signature = signature;

            role = d;
            return true;
        }

        protected override bool TryReadRoleDescriptorChild(XmlDictionaryReader reader, RoleDescriptor role)
        {
            if (base.TryReadRoleDescriptorChild(reader, role))
                return true;

            if (role is AttributeServiceDescriptor attributeServiceDescriptor)
                return TryReadAttributeServiceDescriptorChild(reader, attributeServiceDescriptor);

            if (role is ApplicationServiceDescriptor applicationServiceDescriptor)
                return TryReadApplicationServiceDescriptorChild(reader, applicationServiceDescriptor);

            if (role is PseudonymServiceDescriptor pseudonymServiceDescriptor)
                return TryReadPseudonymServiceDescriptorChild(reader, pseudonymServiceDescriptor);

            if (role is SecurityTokenServiceDescriptor securityTokenServiceDescriptor)
                return TryReadSecurityTokenServiceDescriptorChild(reader, securityTokenServiceDescriptor);

            return false;
        }

        protected virtual bool TryReadPseudonymServiceDescriptorChild(XmlDictionaryReader reader, PseudonymServiceDescriptor pseudonymServiceDescriptor)
        {
            if (WsAddressingSerializer.TryReadEndpointReferenceCollection(reader, Elements.SingleSignOutNotificationEndpoint, Namespace, out var singleSignOutNotificationEndpoint))
                pseudonymServiceDescriptor.SingleSignOutNotificationEndpoint.Add(singleSignOutNotificationEndpoint);
            else if (WsAddressingSerializer.TryReadEndpointReferenceCollection(reader, Elements.PseudonymServiceEndpoint, Namespace, out var pseudonymServiceEndpoint))
                pseudonymServiceDescriptor.PseudonymServiceEndpoint.Add(pseudonymServiceEndpoint);
            else
                return TryReadWebServiceDescriptorChild(reader, pseudonymServiceDescriptor);

            return true;
        }

        protected virtual bool TryReadAttributeServiceDescriptorChild(XmlDictionaryReader reader, AttributeServiceDescriptor attributeServiceDescriptor)
        {
            if (WsAddressingSerializer.TryReadEndpointReferenceCollection(reader, Elements.SingleSignOutNotificationEndpoint, Namespace, out var singleSignOutNotificationEndpoint))
                attributeServiceDescriptor.SingleSignOutNotificationEndpoint.Add(singleSignOutNotificationEndpoint);
            else if (WsAddressingSerializer.TryReadEndpointReferenceCollection(reader, Elements.AttributeServiceEndpoint, Namespace, out var attributeServiceEndpoint))
                attributeServiceDescriptor.AttributeServiceEndpoint.Add(attributeServiceEndpoint);
            else
                return TryReadWebServiceDescriptorChild(reader, attributeServiceDescriptor);

            return true;
        }

        protected virtual bool TryReadSecurityTokenServiceDescriptorChild(XmlDictionaryReader reader, SecurityTokenServiceDescriptor securityTokenServiceDescriptor)
        {
            if (WsAddressingSerializer.TryReadEndpointReferenceCollection(reader, Elements.SecurityTokenServiceEndpoint, Namespace, out var securityTokenServiceEndpoint))
                securityTokenServiceDescriptor.SecurityTokenServiceEndpoint.Add(securityTokenServiceEndpoint);
            else if (WsAddressingSerializer.TryReadEndpointReferenceCollection(reader, Elements.SingleSignOutSubscriptionEndpoint, Namespace, out var singleSignOutSubscriptionEndpoint))
                securityTokenServiceDescriptor.SingleSignOutSubscriptionEndpoint.Add(singleSignOutSubscriptionEndpoint);
            else if (WsAddressingSerializer.TryReadEndpointReferenceCollection(reader, Elements.SingleSignOutNotificationEndpoint, Namespace, out var singleSignOutNotificationEndpoint))
                securityTokenServiceDescriptor.SingleSignOutNotificationEndpoint.Add(singleSignOutNotificationEndpoint);
            else if (WsAddressingSerializer.TryReadEndpointReferenceCollection(reader, Elements.PassiveRequestorEndpoint, Namespace, out var passiveRequestorNotificationEndpoint))
                securityTokenServiceDescriptor.PassiveRequestorEndpoint.Add(passiveRequestorNotificationEndpoint);
            else
                return TryReadWebServiceDescriptorChild(reader, securityTokenServiceDescriptor);

            return true;
        }

        protected virtual bool TryReadApplicationServiceDescriptorChild(XmlDictionaryReader reader, ApplicationServiceDescriptor applicationServiceDescriptor)
        {
            if (WsAddressingSerializer.TryReadEndpointReferenceCollection(reader, Elements.SingleSignOutNotificationEndpoint, Namespace, out var singleSignOutNotificationEndpoint))
                applicationServiceDescriptor.SingleSignOutNotificationEndpoint.Add(singleSignOutNotificationEndpoint);
            else if (WsAddressingSerializer.TryReadEndpointReferenceCollection(reader, Elements.ApplicationServiceEndpoint, Namespace, out var applicationServiceEndpoint))
                applicationServiceDescriptor.ApplicationServiceEndpoint.Add(applicationServiceEndpoint);
            else if (WsAddressingSerializer.TryReadEndpointReferenceCollection(reader, Elements.PassiveRequestorEndpoint, Namespace, out var passiveRequestorNotificationEndpoint))
                applicationServiceDescriptor.PassiveRequestorEndpoint.Add(passiveRequestorNotificationEndpoint);
            else
                return TryReadWebServiceDescriptorChild(reader, applicationServiceDescriptor);

            return true;
        }

        protected virtual bool TryReadWebServiceDescriptorChild(XmlDictionaryReader reader, WebServiceDescriptor webServiceDescriptor)
        {
            if (TryReadLogicalServiceNamesOffered(reader, out var logicalServiceNamesOffered))
                webServiceDescriptor.IssuerNames.AddRange(logicalServiceNamesOffered);
            else if (TryReadTokenTypesOffered(reader, out var tokenTypesOffered))
                webServiceDescriptor.TokenTypesOffered.AddRange(tokenTypesOffered);
            else if (TryReadClaimDialectsOffered(reader, out var claimDialectsOffered))
                webServiceDescriptor.ClaimDialectsOffered.AddRange(claimDialectsOffered);
            else if (TryReadClaimTypes(reader, Elements.ClaimTypesOffered, Namespace, out var claimTypesOffered))
                webServiceDescriptor.ClaimTypesOffered.AddRange(claimTypesOffered);
            else if (TryReadClaimTypes(reader, Elements.ClaimTypesRequested, Namespace, out var claimTypesRequested))
                webServiceDescriptor.ClaimTypesRequested.AddRange(claimTypesRequested);
            else if (TryReadAutomaticPseudonyms(reader, out var automaticPseudonyms))
                webServiceDescriptor.AutomaticPseudonyms = automaticPseudonyms;
            else if (WsAddressingSerializer.TryReadEndpointReferenceCollection(reader, Elements.TargetScopes, Namespace, out var targetScopes))
                webServiceDescriptor.TargetScopes.AddRange(targetScopes);
            else
                return base.TryReadRoleDescriptorChild(reader, webServiceDescriptor);

            return true;
        }

        protected virtual bool TryReadAutomaticPseudonyms(XmlDictionaryReader reader, out bool? automaticPseudonyms)
        {
            if (!reader.TryReadElementContent(Elements.AutomaticPseudonyms, Namespace, out var content)) return Out.False(out automaticPseudonyms);

            if (!bool.TryParse(content, out var parsed))
                // The element has been read, but the contents of the element wasn't a valid boolean value. Default to false.
                return Out.True(false, out automaticPseudonyms);

            automaticPseudonyms = parsed;
            return true;
        }

        protected virtual bool TryReadClaimDialectsOffered(XmlDictionaryReader reader, out List<Uri> claimDialectsOffered)
        {
            if (!reader.IsStartElement(Elements.ClaimDialectsOffered, Namespace)) return Out.False(out claimDialectsOffered);
            var list = new List<Uri>();

            reader.ForEachChild(r =>
            {
                if (TryReadClaimDialect(reader, out var claimDialect))
                {
                    list.Add(claimDialect);
                    return true;
                }
                return false;
            });
            claimDialectsOffered = list;
            return true;
        }

        protected virtual bool TryReadClaimDialect(XmlDictionaryReader reader, out Uri claimDialect)
        {
            if (!reader.IsStartElement(Elements.ClaimDialect, Namespace)) return Out.False(out claimDialect);

            _ = reader.TryReadAttributeAsUri(Attributes.Uri, out var uri);
            _ = reader.ReadOuterXml();
            claimDialect = uri;
            return true;
        }

        protected virtual bool TryReadClaimTypes(XmlDictionaryReader reader, string name, string ns, out List<ClaimType> claimTypes)
        {
            if (!reader.IsStartElement(name, ns)) return Out.False(out claimTypes);
            var list = new List<ClaimType>();

            reader.ForEachChild(r =>
            {
                if (WsAuthorizationSerializer.TryReadClaimType(reader, out var claimType))
                {
                    list.Add(claimType);
                    return true;
                }
                return false;
            });
            claimTypes = list;
            return true;
        }

        protected virtual bool TryReadLogicalServiceNamesOffered(XmlDictionaryReader reader, out List<Uri> logicalServiceNamesOffered)
        {
            if (!reader.IsStartElement(Elements.LogicalServiceNamesOffered, Namespace)) return Out.False(out logicalServiceNamesOffered);
            var list = new List<Uri>();

            reader.ForEachChild(r =>
            {
                if (TryReadIssuerName(reader, out var issuerName))
                {
                    list.Add(issuerName);
                    return true;
                }
                return false;
            });
            logicalServiceNamesOffered = list;
            return true;
        }

        protected virtual bool TryReadIssuerName(XmlDictionaryReader reader, out Uri issuerName)
        {
            if (!reader.IsStartElement(Elements.IssuerName, Namespace)) return Out.False(out issuerName);

            _ = reader.TryReadAttributeAsUri(Attributes.Uri, out var uri);
            _ = reader.ReadOuterXml();
            issuerName = uri;
            return true;
        }

        protected virtual bool TryReadTokenType(XmlDictionaryReader reader, out Uri tokenType)
        {
            if (!reader.IsStartElement(Elements.TokenType, Namespace)) return Out.False(out tokenType);

            _ = reader.TryReadAttributeAsUri(Attributes.Uri, out var uri);
            _ = reader.ReadOuterXml();
            tokenType = uri;
            return true;
        }

        protected virtual bool TryReadTokenTypesOffered(XmlDictionaryReader reader, out List<Uri> tokenTypes)
        {
            if (!reader.IsStartElement(Elements.TokenTypesOffered, Namespace)) return Out.False(out tokenTypes);
            var list = new List<Uri>();

            reader.ForEachChild(r =>
            {
                if (TryReadTokenType(reader, out var tokenType))
                {
                    list.Add(tokenType);
                    return true;
                }
                return false;
            });
            tokenTypes = list;
            return true;
        }

        protected override void ReadRoleDescriptorAttributes(XmlDictionaryReader reader, RoleDescriptor role)
        {
            if (role is AttributeServiceDescriptor attributeServiceDescriptor)
                ReadAttributeServiceDescriptorAttributes(reader, attributeServiceDescriptor);

            if (role is ApplicationServiceDescriptor applicationServiceDescriptor)
                ReadApplicationServiceDescriptorAttributes(reader, applicationServiceDescriptor);

            if (role is PseudonymServiceDescriptor pseudonymServiceDescriptor)
                ReadPseudonymServiceDescriptorAttributes(reader, pseudonymServiceDescriptor);

            if (role is SecurityTokenServiceDescriptor securityTokenServiceDescriptor)
                ReadSecurityTokenServiceDescriptorAttributes(reader, securityTokenServiceDescriptor);

            base.ReadRoleDescriptorAttributes(reader, role);
        }

        protected virtual void ReadAttributeServiceDescriptorAttributes(XmlDictionaryReader reader, AttributeServiceDescriptor attributeServiceDescriptor)
        {
        }

        protected virtual void ReadPseudonymServiceDescriptorAttributes(XmlDictionaryReader reader, PseudonymServiceDescriptor pseudonymServiceDescriptor)
        {
        }

        protected virtual void ReadApplicationServiceDescriptorAttributes(XmlDictionaryReader reader, ApplicationServiceDescriptor applicationServiceDescriptor)
        {
        }

        protected virtual void ReadSecurityTokenServiceDescriptorAttributes(XmlDictionaryReader reader, SecurityTokenServiceDescriptor securityTokenServiceDescriptor)
        {
        }

        protected override void WriteRoleDescriptorAttributes(XmlDictionaryWriter writer, RoleDescriptor role)
        {
            base.WriteRoleDescriptorAttributes(writer, role);
            if (role is ApplicationServiceDescriptor applicationServiceDescriptor)
                WriteApplicationServiceDescriptorAttributes(writer, applicationServiceDescriptor);

            if (role is SecurityTokenServiceDescriptor securityTokenServiceDescriptor)
                WriteSecurityTokenServiceDescriptorAttributes(writer, securityTokenServiceDescriptor);
        }

        protected override void WriteRoleDescriptorChildren(XmlDictionaryWriter writer, RoleDescriptor role)
        {
            base.WriteRoleDescriptorChildren(writer, role);
            if (role is ApplicationServiceDescriptor applicationServiceDescriptor)
                WriteApplicationServiceDescriptorAttributes(writer, applicationServiceDescriptor);

            if (role is SecurityTokenServiceDescriptor securityTokenServiceDescriptor)
                WriteSecurityTokenServiceDescriptorAttributes(writer, securityTokenServiceDescriptor);
        }

        protected virtual void WriteSecurityTokenServiceDescriptorAttributes(XmlDictionaryWriter writer, SecurityTokenServiceDescriptor securityTokenServiceDescriptor)
        {
        }

        protected virtual void WriteSecurityTokenServiceChildren(XmlDictionaryWriter writer, SecurityTokenServiceDescriptor securityTokenServiceDescriptor)
        {
        }

        protected virtual void WriteApplicationServiceDescriptorAttributes(XmlDictionaryWriter writer, ApplicationServiceDescriptor applicationServiceDescriptor)
        {
        }

        protected virtual void WriteApplicationServiceDescriptorChildren(XmlDictionaryWriter writer, ApplicationServiceDescriptor applicationServiceDescriptor)
        {
        }
    }
}

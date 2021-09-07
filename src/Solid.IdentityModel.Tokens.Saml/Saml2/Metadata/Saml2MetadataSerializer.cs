using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using Solid.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using Elements = Solid.IdentityModel.Tokens.Saml2.Metadata.Saml2MetadataConstants.Elements;
using Attributes = Solid.IdentityModel.Tokens.Saml2.Metadata.Saml2MetadataConstants.Attributes;
using System.Linq;

namespace Solid.IdentityModel.Tokens.Saml2.Metadata
{
    public class Saml2MetadataSerializer
    {
        public Saml2Serializer Saml2Serializer { get; }
        protected DSigSerializer DSigSerializer { get; }

        public Saml2MetadataSerializer()
            : this(new Saml2Serializer(), new DSigSerializer())
        {

        }

        public Saml2MetadataSerializer(Saml2Serializer saml2Serializer, DSigSerializer dSigSerializer)
        {
            Saml2Serializer = saml2Serializer;
            DSigSerializer = dSigSerializer;
        }

        public virtual Saml2Metadata ReadSaml2Metadata(XmlDictionaryReader reader)
        {
            if (TryReadSaml2Metadata(reader, out var metadata)) return metadata;
            return null;
        }

        #region Elements

        protected virtual bool TryReadSaml2Metadata(XmlDictionaryReader reader, out Saml2Metadata metadata)
        {
            if (TryReadEntityDescriptor(reader, out var entity)) return Out.True(entity, out metadata);
            if (TryReadEntitiesDescriptor(reader, out var entities)) return Out.True(entities, out metadata);

            return Out.False(out metadata);
        }

        protected virtual bool TryReadEntityDescriptor(XmlDictionaryReader reader, out EntityDescriptor entity)
        {
            if (!reader.IsStartElement(Elements.EntityDescriptor, Saml2MetadataConstants.Namespace))
                return Out.False(out entity);

            var e = new EntityDescriptor();
            ReadEntityDescriptorAttributes(reader, e);
            reader.ForEachChild(r => TryReadEntityDescriptorChild(reader, e), out var signature);
            e.Signature = signature;
            entity = e;

            return true;
        }

        protected virtual bool TryReadEntitiesDescriptor(XmlDictionaryReader reader, out EntitiesDescriptor entities)
        {
            if (!reader.IsStartElement(Elements.EntitiesDescriptor, Saml2MetadataConstants.Namespace))
                return Out.False(out entities);

            var e = new EntitiesDescriptor();
            reader.ForEachChild(r => TryReadEntitiesDescriptorChild(r, e), out var signature);
            e.Signature = signature;
            entities = e;
            return true;
        }

        protected virtual bool TryReadIdpSsoDescriptor(XmlDictionaryReader reader, out IdpSsoDescriptor idpSso)
        {
            if (!reader.IsStartElement(Elements.IdpSsoDescriptor, Saml2MetadataConstants.Namespace))
                return Out.False(out idpSso);

            var idp = new IdpSsoDescriptor();
            ReadIdpSsoDescriptorAttributes(reader, idp);
            reader.ForEachChild(r => TryReadIdpSsoDescriptorChild(r, idp), out var signature);
            idp.Signature = signature;
            idpSso = idp;
            return true;
        }

        protected virtual bool TryReadSpSsoDescriptor(XmlDictionaryReader reader, out SpSsoDescriptor spSso)
        {
            if (!reader.IsStartElement(Elements.SpSsoDescriptor, Saml2MetadataConstants.Namespace))
                return Out.False(out spSso);

            var sp = new SpSsoDescriptor();
            ReadSpSsoDescriptorAttributes(reader, sp);
            reader.ForEachChild(r => TryReadSpSsoDescriptorChild(r, sp), out var signature);
            sp.Signature = signature;
            spSso = sp;
            return true;
        }

        protected virtual bool TryReadRoleDescriptor(XmlDictionaryReader reader, out RoleDescriptor role)
        {
            if (!reader.IsStartElement(Elements.RoleDescriptor, Saml2MetadataConstants.Namespace))
                return Out.False(out role);

            var d = new RoleDescriptor();
            ReadRoleDescriptorAttributes(reader, d);

            reader.ForEachChild(r => TryReadRoleDescriptorChild(r, d), out var signature);
            d.Signature = signature;

            role = d;
            return true;
        }

        protected virtual bool TryReadAuthnAuthorityDescriptor(XmlDictionaryReader reader, out AuthnAuthorityDescriptor authnAuthorityDescriptor)
        {
            if (!reader.IsStartElement(Elements.AuthnAuthorityDescriptor, Saml2MetadataConstants.Namespace))
                return Out.False(out authnAuthorityDescriptor);

            var authority = new AuthnAuthorityDescriptor();
            ReadAuthnAuthorityDescriptorAttributes(reader, authority);
            reader.ForEachChild(r => TryReadAuthnAuthorityDescriptorChild(r, authority), out var signature);
            authority.Signature = signature;
            authnAuthorityDescriptor = authority;
            return true;
        }

        protected virtual bool TryReadAttributeAuthorityDescriptor(XmlDictionaryReader reader, out AttributeAuthorityDescriptor attributeAuthorityDescriptor)
        {
            if (!reader.IsStartElement(Elements.AttributeAuthorityDescriptor, Saml2MetadataConstants.Namespace))
                return Out.False(out attributeAuthorityDescriptor);

            var authority = new AttributeAuthorityDescriptor();
            ReadAttributeAuthorityDescriptorAttributes(reader, authority);
            reader.ForEachChild(r => TryReadAttributeAuthorityDescriptorChild(r, authority), out var signature);
            authority.Signature = signature;
            attributeAuthorityDescriptor = authority;
            return true;
        }


        protected virtual bool TryReadPdpDescriptor(XmlDictionaryReader reader, out PdpDescriptor pdpDescriptor)
        {
            if (!reader.IsStartElement(Elements.PdpDescriptor, Saml2MetadataConstants.Namespace))
                return Out.False(out pdpDescriptor);

            var pdp = new PdpDescriptor();
            ReadPdpDescriptorAttributes(reader, pdp);
            reader.ForEachChild(r => TryReadPdpDescriptorChild(r, pdp), out var signature);
            pdp.Signature = signature;
            pdpDescriptor = pdp;
            return true;
        }

        protected virtual bool TryReadAffiliationDescriptor(XmlDictionaryReader reader, out AffiliationDescriptor affiliationDescriptor)
        {
            if (!reader.IsStartElement(Elements.AffiliationDescriptor, Saml2MetadataConstants.Namespace))
                return Out.False(out affiliationDescriptor);

            var affiliation = new AffiliationDescriptor();
            ReadAffiliationDescriptorAttributes(reader, affiliation);
            reader.ForEachChild(r => TryReadAffiliationDescriptorChild(r, affiliation), out var signature);
            affiliation.Signature = signature;
            affiliationDescriptor = affiliation;
            return true;
        }

        protected virtual bool TryReadSaml2Attribute(XmlDictionaryReader reader, out Saml2Attribute saml2Attribute)
        {
            if (!reader.IsStartElement(Saml2Constants.Elements.Attribute, Saml2Constants.Namespace))
                return Out.False(out saml2Attribute);

            var attribute = Saml2Serializer.ReadAttribute(reader);
            saml2Attribute = attribute;
            return true;
        }

        protected virtual bool TryReadAttributeConsumingService(XmlDictionaryReader reader, out AttributeConsumingService attributeConsumingService)
        {
            if (!reader.IsStartElement(Elements.AttributeConsumingService, Saml2MetadataConstants.Namespace))
                return Out.False(out attributeConsumingService);

            var service = new AttributeConsumingService();
            if (reader.TryReadAttribute(Attributes.Index, out var indexStr) && ushort.TryParse(indexStr, out var index))
                service.Index = index;

            if (reader.TryReadAttribute(Attributes.IsDefault, out var isDefaultStr) && bool.TryParse(isDefaultStr, out var isDefault))
                service.IsDefault = isDefault;

            reader.ForEachChild(r =>
            {
                if (TryReadElementContentAsLocalizedName(reader, Elements.ServiceName, Saml2MetadataConstants.Namespace, out var name))
                    service.Name.Add(name);
                else if (TryReadElementContentAsLocalizedName(reader, Elements.ServiceDescription, Saml2MetadataConstants.Namespace, out var description))
                    service.Description.Add(description);
                else if (TryReadRequestedAttribute(reader, out var attribute))
                    service.RequestedAttribute.Add(attribute);
                else
                    return false;

                return true;
            });

            attributeConsumingService = service;
            return true;
        }

        protected virtual bool TryReadRequestedAttribute(XmlDictionaryReader reader, out RequestedSaml2Attribute requestedAttribute)
        {
            if (!reader.IsStartElement(Elements.RequestedAttribute, Saml2MetadataConstants.Namespace))
                return Out.False(out requestedAttribute);

            if (!reader.TryReadAttribute(Saml2Constants.Attributes.Name, out var name))
                return Out.False(out requestedAttribute);

            var attribute = new RequestedSaml2Attribute(name);

            if (reader.TryReadAttributeAsUri(Saml2Constants.Attributes.NameFormat, out var nameFormat))
                attribute.NameFormat = nameFormat;
            if (reader.TryReadAttribute(Saml2Constants.Attributes.FriendlyName, out var friendlyName))
                attribute.FriendlyName = friendlyName;

            // Should we read attribute values?
            reader.ForEachChild(_ => false);
            requestedAttribute = attribute;
            return true;
        }

        protected virtual bool TryReadOrganization(XmlDictionaryReader reader, out Organization organization)
        {
            if (!reader.IsStartElement(Elements.Organization, Saml2MetadataConstants.Namespace))
                return Out.False(out organization);

            var o = new Organization();
            reader.ForEachChild(r =>
            {
                if (TryReadElementContentAsLocalizedName(reader, Elements.OrganizationName, Saml2MetadataConstants.Namespace, out var organizationName))
                    o.Name.Add(organizationName);
                else if (TryReadElementContentAsLocalizedName(reader, Elements.OrganizationDisplayName, Saml2MetadataConstants.Namespace, out var organizationDisplayName))
                    o.DisplayName.Add(organizationDisplayName);
                else if (TryReadElementContentAsLocalizedUri(reader, Elements.OrganizationUrl, Saml2MetadataConstants.Namespace, out var organizationUrl))
                    o.Url.Add(organizationUrl);
                else
                    return false;

                return true;
            });
            organization = o;
            return true;
        }

        protected virtual bool TryReadKeyDescriptor(XmlDictionaryReader reader, out KeyDescriptor keyDescriptor)
        {
            if (!reader.IsStartElement(Elements.KeyDescriptor, Saml2MetadataConstants.Namespace))
                return Out.False(out keyDescriptor);

            var d = new KeyDescriptor();
            if (reader.TryReadAttribute(Attributes.Use, out var str) && !Enum.TryParse<KeyUse>(str, out var use))
                d.Use = use;

            reader.ForEachChild(r =>
            {
                if (r.IsStartElement(XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace))
                    d.KeyInfo = DSigSerializer.ReadKeyInfo(reader);
                else
                    return false;

                return true;
            });

            keyDescriptor = d;
            return true;
        }

        protected virtual bool TryReadIndexedEndpoint(XmlDictionaryReader reader, string localName, string ns, out IndexedEndpoint indexedEndpoint)
        {
            if (!reader.IsStartElement(Elements.IndexedEndpoint, Saml2MetadataConstants.Namespace)) return Out.False(out indexedEndpoint);

            var e = new IndexedEndpoint();
            ReadIndexedEndpointAttributes(reader, e);
            indexedEndpoint = e;
            return true;
        }

        protected virtual bool TryReadEndpoint(XmlDictionaryReader reader, string localName, string ns, out Endpoint endpoint)
        {
            if (!reader.IsStartElement(Elements.Endpoint, Saml2MetadataConstants.Namespace)) return Out.False(out endpoint);

            var e = new Endpoint();
            ReadEndpointAttributes(reader, e);
            endpoint = e;
            return true;
        }

        protected virtual bool TryReadContactPerson(XmlDictionaryReader reader, out ContactPerson contact)
        {
            if (!reader.IsStartElement(Elements.ContactPerson, Saml2MetadataConstants.Namespace))
                return Out.False(out contact);

            var c = new ContactPerson();

            if (reader.TryReadAttribute(Attributes.ContactType, out var value) && Enum.TryParse<ContactType>(value, true, out var contactType))
                c.ContactType = contactType;

            reader.ForEachChild(r => TryReadContactPersonChild(r, c));

            contact = c;
            return true;
        }

        protected virtual bool TryReadAdditionalMetadataLocation(XmlDictionaryReader reader, out AdditionalMetadataLocation additionalMetadataLocation)
        {
            if (!reader.IsStartElement(Elements.AdditionalMetadataLocation, Saml2MetadataConstants.Namespace))
                return Out.False(out additionalMetadataLocation);

            var location = new AdditionalMetadataLocation();

            if (reader.TryReadAttribute(Attributes.Namespace, out var ns))
                location.Namespace = ns;

            var content = reader.ReadElementContentAsUri();
            location.Value = content;
            additionalMetadataLocation = location;
            return true;
        }

        #endregion Elements

        #region Child elements

        protected virtual bool TryReadEntitiesDescriptorChild(XmlDictionaryReader reader, EntitiesDescriptor entities)
        {
            if (TryReadSaml2Metadata(reader, out var metadata))
                entities.Items.Add(metadata);
            else
                return false;

            return true;
        }

        protected virtual bool TryReadEntityDescriptorChild(XmlDictionaryReader reader, EntityDescriptor entity)
        {
            if (TryReadRoleDescriptor(reader, out var roleDescriptor))
                entity.Items.Add(roleDescriptor);
            else if (TryReadIdpSsoDescriptor(reader, out var idp))
                entity.Items.Add(idp);
            else if (TryReadSpSsoDescriptor(reader, out var sp))
                entity.Items.Add(sp);
            else if (TryReadAffiliationDescriptor(reader, out var affiliation))
                entity.Items.Add(affiliation);
            else if (TryReadAttributeAuthorityDescriptor(reader, out var attributeAuthority))
                entity.Items.Add(attributeAuthority);
            else if (TryReadAuthnAuthorityDescriptor(reader, out var authnAuthority))
                entity.Items.Add(authnAuthority);
            else if (TryReadPdpDescriptor(reader, out var pdp)) 
                entity.Items.Add(pdp);
            else if (TryReadOrganization(reader, out var organization))
                entity.Organization = organization;
            else
                return TryReadSaml2MetadataChild(reader, entity);

            return true;
        }

        protected virtual bool TryReadSaml2MetadataChild(XmlDictionaryReader reader, Saml2Metadata metadata)
        {
            if (TryReadContactPerson(reader, out var contact))
                metadata.ContactPerson.Add(contact);
            else if (TryReadAdditionalMetadataLocation(reader, out var additionalMetadataLocation))
                metadata.AdditionalMetadataLocation.Add(additionalMetadataLocation);
            else
                return false;

            return true;
        }

        protected virtual bool TryReadRoleDescriptorChild(XmlDictionaryReader reader, RoleDescriptor role)
        {
            if (TryReadContactPerson(reader, out var contact))
                role.ContactPerson.Add(contact);
            else if (TryReadKeyDescriptor(reader, out var key))
                role.KeyDescriptors.Add(key);
            else if (TryReadOrganization(reader, out var organization))
                role.Organization = organization;
            else
                return false;

            return true;
        }

        protected virtual bool TryReadContactPersonChild(XmlDictionaryReader reader, ContactPerson contact)
        {
            if (TryReadElementContent(reader, Elements.Company, Saml2MetadataConstants.Namespace, out var company))
                contact.Company = company;
            else if (TryReadElementContent(reader, Elements.EmailAddress, Saml2MetadataConstants.Namespace, out var emailAddress))
                contact.EmailAddresses.Add(emailAddress);
            else if (TryReadElementContent(reader, Elements.TelephoneNumber, Saml2MetadataConstants.Namespace, out var telephoneNumber))
                contact.TelephoneNumbers.Add(telephoneNumber);
            else if (TryReadElementContent(reader, Elements.GivenName, Saml2MetadataConstants.Namespace, out var givenName))
                contact.GivenName = givenName;
            else if (TryReadElementContent(reader, Elements.SurName, Saml2MetadataConstants.Namespace, out var surName))
                contact.SurName = surName;
            else
                return false;

            return true;
        }

        protected virtual bool TryReadIdpSsoDescriptorChild(XmlDictionaryReader reader, IdpSsoDescriptor idp)
        {
            if (TryReadEndpoint(reader, Elements.SingleSignOnService, Saml2MetadataConstants.Namespace, out var singleSignOnService))
                idp.SingleSignOnService.Add(singleSignOnService);
            else if (TryReadEndpoint(reader, Elements.NameIdMappingService, Saml2MetadataConstants.Namespace, out var nameIdMappingService))
                idp.NameIdMappingService.Add(nameIdMappingService);
            else if (TryReadEndpoint(reader, Elements.AssertionIdRequestService, Saml2MetadataConstants.Namespace, out var assertionIdRequestService))
                idp.AssertionIdRequestService.Add(assertionIdRequestService);
            else if (TryReadElementContentAsUri(reader, Elements.AttributeProfile, Saml2MetadataConstants.Namespace, out var attributeProfile))
                idp.AttributeProfile.Add(attributeProfile);
            else if (TryReadSaml2Attribute(reader, out var saml2Attribute))
                idp.Attributes.Add(saml2Attribute);
            else
                return TryReadSsoDescriptorChild(reader, idp);

            return true;
        }

        protected virtual bool TryReadSpSsoDescriptorChild(XmlDictionaryReader reader, SpSsoDescriptor sp)
        {
            if (TryReadIndexedEndpoint(reader, Elements.AssertionConsumerService, Saml2MetadataConstants.Namespace, out var assertionConsumerService))
                sp.AssertionConsumerService.Add(assertionConsumerService);
            else if (TryReadAttributeConsumingService(reader, out var attributeConsumingService))
                sp.AttributeConsumingService.Add(attributeConsumingService);
            else
                return TryReadSsoDescriptorChild(reader, sp);

            return true;
        }

        protected virtual bool TryReadSsoDescriptorChild(XmlDictionaryReader reader, SsoDescriptor sso)
        {
            if (TryReadIndexedEndpoint(reader, Elements.ArtifactResolutionService, Saml2MetadataConstants.Namespace, out var artifactResolutionService))
                sso.ArtifactResolutionService.Add(artifactResolutionService);
            else if (TryReadEndpoint(reader, Elements.SingleLogoutService, Saml2MetadataConstants.Namespace, out var singleLogoutService))
                sso.SingleLogoutService.Add(singleLogoutService);
            else if (TryReadEndpoint(reader, Elements.ManageNameIdService, Saml2MetadataConstants.Namespace, out var manageNameIdService))
                sso.ManageNameIdService.Add(manageNameIdService);
            else if (TryReadElementContentAsUri(reader, Elements.NameIdFormat, Saml2MetadataConstants.Namespace, out var nameIdFormat))
                sso.NameIdFormat.Add(nameIdFormat);
            else
                return TryReadRoleDescriptorChild(reader, sso);

            return true;
        }

        protected virtual bool TryReadAuthnAuthorityDescriptorChild(XmlDictionaryReader reader, AuthnAuthorityDescriptor authority)
        {
            if (TryReadEndpoint(reader, Elements.AuthnQueryService, Saml2MetadataConstants.Namespace, out var authnQueryService))
                authority.AuthnQueryService.Add(authnQueryService);
            else if (TryReadEndpoint(reader, Elements.AssertionIdRequestService, Saml2MetadataConstants.Namespace, out var assertionIdRequestService))
                authority.AssertionIdRequestService.Add(assertionIdRequestService);
            else if (TryReadElementContentAsUri(reader, Elements.NameIdFormat, Saml2MetadataConstants.Namespace, out var nameIdFormat))
                authority.NameIdFormat.Add(nameIdFormat);
            else
                return TryReadRoleDescriptorChild(reader, authority);

            return true;
        }

        protected virtual bool TryReadAttributeAuthorityDescriptorChild(XmlDictionaryReader reader, AttributeAuthorityDescriptor authority)
        {
            if (TryReadEndpoint(reader, Elements.AttributeService, Saml2MetadataConstants.Namespace, out var attributeService))
                authority.AttributeService.Add(attributeService);
            else if (TryReadEndpoint(reader, Elements.AssertionIdRequestService, Saml2MetadataConstants.Namespace, out var assertionIdRequestService))
                authority.AssertionIdRequestService.Add(assertionIdRequestService);
            else if (TryReadElementContentAsUri(reader, Elements.NameIdFormat, Saml2MetadataConstants.Namespace, out var nameIdFormat))
                authority.NameIdFormat.Add(nameIdFormat);
            else if (TryReadSaml2Attribute(reader, out var attribute))
                authority.Attributes.Add(attribute);
            else if (TryReadElementContentAsUri(reader, Elements.AttributeProfile, Saml2MetadataConstants.Namespace, out var attributeProfile))
                authority.AttributeProfile.Add(attributeProfile);
            else
                return TryReadRoleDescriptorChild(reader, authority);

            return true;
        }

        protected virtual bool TryReadPdpDescriptorChild(XmlDictionaryReader reader, PdpDescriptor pdp)
        {
            if (TryReadEndpoint(reader, Elements.AuthzService, Saml2MetadataConstants.Namespace, out var authzService))
                pdp.AuthzService.Add(authzService);
            else if (TryReadEndpoint(reader, Elements.AssertionIdRequestService, Saml2MetadataConstants.Namespace, out var assertionIdRequestService))
                pdp.AssertionIdRequestService.Add(assertionIdRequestService);
            else if (TryReadElementContentAsUri(reader, Elements.NameIdFormat, Saml2MetadataConstants.Namespace, out var nameIdFormat))
                pdp.NameIdFormat.Add(nameIdFormat);
            else
                return TryReadRoleDescriptorChild(reader, pdp);

            return true;
        }

        protected virtual bool TryReadAffiliationDescriptorChild(XmlDictionaryReader reader, AffiliationDescriptor affiliation)
        {
            if (TryReadKeyDescriptor(reader, out var keyDescriptor))
                affiliation.KeyDescriptor.Add(keyDescriptor);
            else if (TryReadElementContentAsUri(reader, Elements.AffiliateMember, Saml2MetadataConstants.Namespace, out var affiliateMember))
                affiliation.AffiliateMember.Add(affiliateMember);
            else
                return false;

            return true;
        }
        #endregion Child elements

        #region Attributes

        protected virtual void ReadIndexedEndpointAttributes(XmlDictionaryReader reader, IndexedEndpoint indexedEndpoint)
        {
            if (reader.TryReadAttribute(Attributes.Index, out var indexStr) && ushort.TryParse(indexStr, out var index))
                indexedEndpoint.Index = index;

            if (reader.TryReadAttribute(Attributes.IsDefault, out var isDefaultStr) && bool.TryParse(isDefaultStr, out var isDefault))
                indexedEndpoint.IsDefault = isDefault;

            ReadEndpointAttributes(reader, indexedEndpoint);
        }

        protected virtual void ReadEndpointAttributes(XmlDictionaryReader reader, Endpoint endpoint)
        {
            if (reader.TryReadAttributeAsUri(Attributes.Binding, out var binding))
                endpoint.Binding = binding;

            if (reader.TryReadAttributeAsUri(Attributes.Location, out var location))
                endpoint.Location = location;

            if (reader.TryReadAttributeAsUri(Attributes.ResponseLocation, out var responseLocation))
                endpoint.ResponseLocation = responseLocation;
        }

        protected virtual void ReadEntityDescriptorAttributes(XmlDictionaryReader reader, EntityDescriptor entity)
        {
            if (reader.TryReadAttributeAsUri(Attributes.EntityId, out var entityId))
                entity.EntityId = entityId;

            ReadSaml2MetadataAttributes(reader, entity);
        }

        protected virtual void ReadSaml2MetadataAttributes(XmlDictionaryReader reader, Saml2Metadata metadata) 
            => ReadBaseAttributes(reader, metadata);

        protected virtual void ReadIdpSsoDescriptorAttributes(XmlDictionaryReader reader, IdpSsoDescriptor idp)
        {
            if (reader.TryReadAttribute(Attributes.WantAuthnRequestsSigned, out var wantAuthnRequestSignedValue) && bool.TryParse(wantAuthnRequestSignedValue, out var wantAuthnRequestSigned))
                idp.WantAuthnRequestsSigned = wantAuthnRequestSigned;

            ReadSsoDescriptorAttributes(reader, idp);
        }

        protected virtual void ReadSpSsoDescriptorAttributes(XmlDictionaryReader reader, SpSsoDescriptor sp)
        {
            if (reader.TryReadAttribute(Attributes.AuthnRequestsSigned, out var authnRequestsSignedValue) && bool.TryParse(authnRequestsSignedValue, out var authnRequestsSigned))
                sp.AuthnRequestsSigned = authnRequestsSigned;

            if (reader.TryReadAttribute(Attributes.WantAssertionsSigned, out var wantAssertionsSignedValue) && bool.TryParse(wantAssertionsSignedValue, out var wantAssertionsSigned))
                sp.WantAssertionsSigned = wantAssertionsSigned;

            ReadSsoDescriptorAttributes(reader, sp);
        }

        protected virtual void ReadSsoDescriptorAttributes(XmlDictionaryReader reader, SsoDescriptor sso) 
            => ReadRoleDescriptorAttributes(reader, sso);

        protected virtual void ReadRoleDescriptorAttributes(XmlDictionaryReader reader, RoleDescriptor role)
        {
            if(reader.TryReadAttribute(Attributes.ProtocolSupportEnumeration, out var protocolSupportEnumeration))
            {
                var list = protocolSupportEnumeration
                    .Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)
                    .Where(v => Uri.IsWellFormedUriString(v, UriKind.Absolute))
                    .Select(v => new Uri(v))
                    .ToList()
                ; 
                role.ProtocolsSupported = list;
            }

            ReadBaseAttributes(reader, role);
        }

        protected virtual void ReadAttributeAuthorityDescriptorAttributes(XmlDictionaryReader reader, AttributeAuthorityDescriptor authority)
            => ReadRoleDescriptorAttributes(reader, authority);

        protected virtual void ReadPdpDescriptorAttributes(XmlDictionaryReader reader, PdpDescriptor pdp)
            => ReadRoleDescriptorAttributes(reader, pdp);

        protected virtual void ReadAffiliationDescriptorAttributes(XmlDictionaryReader reader, AffiliationDescriptor affiliation)
        {
            if (reader.TryReadAttributeAsUri(Attributes.AffiliationOwnerId, out var affiliationOwnerId))
                affiliation.AffiliationOwnerId = affiliationOwnerId;
            ReadBaseAttributes(reader, affiliation);
        }

        protected virtual void ReadBaseAttributes(XmlDictionaryReader reader, DescriptorBase descriptor)
        {
            if (reader.TryReadAttribute(Saml2Constants.Attributes.ID, out var id))
                descriptor.Id = id;
            if (reader.TryReadAttributeAsTimeSpan(Attributes.CacheDuration, out var cacheDuration))
                descriptor.CacheDuration = cacheDuration;
            if (reader.TryReadAttributeAsDateTime(Attributes.ValidUntil, out var validUntil))
                descriptor.ValidUntil = validUntil;
        }

        protected virtual void ReadAuthnAuthorityDescriptorAttributes(XmlDictionaryReader reader, AuthnAuthorityDescriptor authority)
            => ReadRoleDescriptorAttributes(reader, authority);

        #endregion Attributes

        #region Utility
        protected virtual bool TryReadElementContent(XmlDictionaryReader reader, string localName, string ns, out string value)
        {
            if (!reader.IsStartElement(localName, ns)) return Out.False(out value);

            value = reader.ReadElementContentAsString();
            return true;
        }

        protected virtual bool TryReadElementContentAsUri(XmlDictionaryReader reader, string localName, string ns, out Uri value)
        {
            if (!reader.IsStartElement(localName, ns)) return Out.False(out value);

            var content = reader.ReadElementContentAsUri();
            value = content;
            return true;
        }

        protected virtual bool TryReadElementContentAsLocalizedName(XmlDictionaryReader reader, string localName, string ns, out LocalizedName value)
        {
            if (!reader.IsStartElement(localName, ns)) return Out.False(out value);
            var lang = reader.GetAttribute("lang");
            if (string.IsNullOrWhiteSpace(lang)) return Out.False(out value);

            var content = reader.ReadElementContentAsString();

            var localized = new LocalizedName
            {
                Lang = lang,
                Value = content
            };
            value = localized;
            return true;
        }

        protected virtual bool TryReadElementContentAsLocalizedUri(XmlDictionaryReader reader, string localName, string ns, out LocalizedUri value)
        {
            if (!reader.IsStartElement(localName, ns)) return Out.False(out value);
            var lang = reader.GetAttribute("lang");
            if (string.IsNullOrWhiteSpace(lang)) return Out.False(out value);

            var content = reader.ReadElementContentAsUri();

            var localized = new LocalizedUri
            {
                Lang = lang,
                Value = content
            };
            value = localized;
            return true;
        }

        protected virtual EnvelopedSignatureReader CreateEnvelopedSignatureReader(XmlReader reader) 
            => new EnvelopedSignatureReader(reader);

        protected virtual bool IsValidEntityId(Uri value)
        {
            if (value == null) return false;
            if (!value.IsAbsoluteUri) return false;
            var absolute = value.AbsoluteUri;
            return absolute.Length <= 1024;
        }
        #endregion
    }
}

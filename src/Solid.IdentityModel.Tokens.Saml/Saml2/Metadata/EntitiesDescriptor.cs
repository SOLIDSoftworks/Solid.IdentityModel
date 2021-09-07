using System.Collections.Generic;
using System.Linq;

namespace Solid.IdentityModel.Tokens.Saml2.Metadata
{
    public class EntitiesDescriptor : Saml2Metadata
    {
        public IEnumerable<EntityDescriptor> Entities => Items.OfType<EntityDescriptor>();
        public IEnumerable<EntitiesDescriptor> EntityCollections => Items.OfType<EntitiesDescriptor>();
    }
}

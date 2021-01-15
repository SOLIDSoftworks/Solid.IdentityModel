using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.IdentityModel.Xml
{
    public static class Out
    {
        public static bool False<T>(out T obj)
        {
            obj = default;
            return false;
        }
    }
}

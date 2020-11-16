using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.IdentityModel.Tokens.Crypto
{
    public static class KeyWrapAlgorithms
    {
        public static readonly string RsaOaepAlgorithm = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

        public static readonly KeyWrapAlgorithmName RsaOaep = new KeyWrapAlgorithmName(RsaOaepAlgorithm);
    }
}

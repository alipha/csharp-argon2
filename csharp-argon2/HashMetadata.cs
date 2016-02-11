using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Argon2
{
    public class HashMetadata
    {
        public Argon2Type ArgonType { get; set; }

        public int MemoryCost { get; set; }

        public int TimeCost { get; set; }

        public int Parallelism { get; set; }

        public string Base64Salt { get; set; }

        public string Base64Hash { get; set; }


        public byte[] GetSaltBytes() { return Convert.FromBase64String(Base64Salt); }

        public byte[] GetHashBytes() { return Convert.FromBase64String(Base64Hash); }
    }
}

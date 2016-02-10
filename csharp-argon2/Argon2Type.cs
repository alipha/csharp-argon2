using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Argon2
{
    public enum Argon2Type
    {
        Argon2d = 0,   /* Dependent (vulnerable to side-channel attacks) */
        Argon2i = 1    /* Independent (safe from side-channel attacks) */
    }
}

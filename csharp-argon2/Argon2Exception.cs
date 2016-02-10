using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Argon2
{
    public class Argon2Exception : Exception
    {
        public Argon2Exception(string action, Argon2Error error) : base(string.Format("Error while Argon2 {0}: ({1}) {2}", action, (int)error, error.ToString())) {}
    }
}

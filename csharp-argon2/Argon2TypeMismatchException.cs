
namespace Liphsoft.Crypto.Argon2
{
    /// <summary>
    /// 
    /// </summary>
    public class Argon2TypeMismatchException : Argon2Exception
    {
        /// <summary>
        /// Thrown if PasswordHasher.ReproduceKey is provided an Argon2Type in its metadata which does not match
        /// the ArgonType of the PasswordHasher object.
        /// This is important that they match in order to prevent an attacker from supplying Argon2Type.Argon2d in the
        /// metadata and tricking the PasswordHasher object to use an algorithm vulnerable to side-channel attacks.
        /// </summary>
        /// <param name="action">Which method the exception originated from</param>
        public Argon2TypeMismatchException(string action) : base(action + " (mismatched Argon2Type)", Argon2Error.DECODING_FAIL) { }
    }
}

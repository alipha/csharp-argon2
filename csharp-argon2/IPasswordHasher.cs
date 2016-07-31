using System.Text;

namespace Liphsoft.Crypto.Argon2
{
    /// <summary>
    /// IPasswordHasher is an interface for creating Argon2 hashes and verifying them
    /// </summary>
    public interface IPasswordHasher
    {
        #region Properties

        /// <summary>
        /// How many iterations of the Argon2 hash to perform
        /// </summary>
        uint TimeCost { get; set; }

        /// <summary>
        /// How much memory to use while hashing in kibibytes (KiB)
        /// </summary>
        uint MemoryCost { get; set; }

        /// <summary>
        /// How many threads to use while hashing
        /// </summary>
        uint Parallelism { get; set; }

        /// <summary>
        /// The type of Argon2 hashing algorithm to use
        /// Argon2d - The memory access is dependent upon the hash value (vulnerable to side-channel attacks)
        /// Argon2i - The memory access is independent upon the hash value (safe from side-channel atacks)
        /// </summary>
        Argon2Type ArgonType { get; set; }

        /// <summary>
        /// Length of the generated raw hash in bytes
        /// </summary>
        uint HashLength { get; set; }

        /// <summary>
        /// How strings should be decoded when passed to the Hash method.
        /// The default is Encoding.UTF8.
        /// </summary>
        Encoding StringEncoding { get; set; }

        #endregion


        #region Hash Methods

        /// <summary>
        /// Hash the password using Argon2 with a cryptographically-secure, random, 16-byte salt.
        /// This is the only overload of the Hash method that the typical user will need to use for password storage. The other overloads are provided for interoperability purposes.
        /// Do not compare two Argon2 hashes directly. Instead, use the Verify or VerifyAndUpdate methods.
        /// <param name="password">A string representing the password to be hashed. The password is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <returns>A formatted string representing the hashed password, encoded with the parameters used to perform the hash</returns>
        /// </summary>
        string Hash(string password);

        /// <summary>
        /// Hash the raw password bytes using Argon2 with a cryptographically-secure, random, 16-byte salt.
        /// Do not compare two Argon2 hashes directly. Instead, use the Verify or VerifyAndUpdate methods.
        /// <param name="password">The raw bytes of the password to be hashed</param>
        /// <returns>A formatted string representing the hashed password, encoded with the parameters used to perform the hash</returns>
        /// </summary>
        string Hash(byte[] password);

        /// <summary>
        /// Hash the password using Argon2 with the specified salt.
        /// Unless you need to specify your own salt for interoperability purposes, prefer the Hash(string password) overload instead.
        /// Do not compare two Argon2 hashes directly. Instead, use the Verify or VerifyAndUpdate methods.
        /// <param name="password">A string representing the password to be hashed. The password is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <param name="salt">A string representing the salt to be used for the hash. The salt must be at least 8 bytes. The salt is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <returns>A formatted string representing the hashed password, encoded with the parameters used to perform the hash</returns>
        /// </summary>
        string Hash(string password, string salt);

        /// <summary>
        /// Hash the raw password bytes using Argon2 with the specified salt bytes.
        /// Unless you need to specify your own salt for interoperability purposes, prefer the Hash(byte[] password) overload instead.
        /// Do not compare two Argon2 hashes directly. Instead, use the Verify or VerifyAndUpdate methods.
        /// <param name="password">The raw bytes of the password to be hashed</param>
        /// <param name="salt">The raw salt bytes to be used for the hash. The salt must be at least 8 bytes.</param>
        /// <returns>A formatted string representing the hashed password, encoded with the parameters used to perform the hash</returns>
        /// </summary>
        string Hash(byte[] password, byte[] salt);

        #endregion


        #region HashRaw Methods

        /// <summary>
        /// Hash the password using Argon2 with the specified salt. The HashRaw methods may be used for password-based key derivation.
        /// Unless you're using HashRaw for key deriviation or for interoperability purposes, the Hash methods should be used in favor of the HashRaw methods. 
        /// <param name="password">A string representing the password to be hashed. The password is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <param name="salt">A string representing the salt to be used for the hash. The salt must be at least 8 bytes. The salt is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <returns>A byte array containing only the resulting hash</returns>
        /// </summary>
        byte[] HashRaw(string password, string salt);

        /// <summary>
        /// Hash the password using Argon2 with the specified salt. The HashRaw methods may be used for password-based key derivation.
        /// Unless you're using HashRaw for key deriviation or for interoperability purposes, the Hash methods should be used in favor of the HashRaw methods.
        /// <param name="password">The raw bytes of the password to be hashed</param>
        /// <param name="salt">The raw salt bytes to be used for the hash. The salt must be at least 8 bytes.</param>
        /// <returns>A byte array containing only the resulting hash</returns>
        /// </summary>
        byte[] HashRaw(byte[] password, byte[] salt);

        #endregion


        #region Verify Methods

        /// <summary>
        /// Hashes the password and verifies that the password results in the specified hash.
        /// The ArgonType must of this PasswordHasher object must match what was used to generate expectedHash.
        /// The other parameters (timeCost, etc.) do not need to match and the parameters embedded in the expectedHash will be used.
        /// <param name="expectedHash">Hashing the password should result in this hash</param>
        /// <param name="password">The password to hash and compare its result to expectedHash. The password is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <returns>Whether the password results in the expectedHash when hashed</returns>
        /// </summary>
        bool Verify(string expectedHash, string password);

        /// <summary>
        /// Hashes the raw password bytes and verifies that the password results in the specified hash.
        /// The ArgonType must of this PasswordHasher object must match what was used to generate expectedHash.
        /// The other parameters (timeCost, etc.) do not need to match and the parameters embedded in the expectedHash will be used.
        /// <param name="expectedHash">Hashing the password should result in this hash</param>
        /// <param name="password">The raw password bytes to hash and compare its result to expectedHash</param>
        /// <returns>Whether the password results in the expectedHash when hashed</returns>
        /// </summary>
        bool Verify(string expectedHash, byte[] password);

        /// <summary>
        /// Hashes the password and verifies that the password results in the specified hash. (See Verify method)
        /// If the password verification is successful, this method checks to see if the memory cost, time cost, and parallelism
        /// match the parameters the PasswordHasher object was constructed with. If they do not much, then the password is rehashed
        /// using the new parameters and the result is outputted via the newFormattedHash parameter.
        /// <param name="expectedHash">Hashing the password should result in this hash</param>
        /// <param name="password">The password to hash and compare its result to expectedHash. The password is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <param name="isUpdated">Whether the cost parameters of expectedHash differ from the PasswordHasher object and if the password was rehashed using th new parameters. This is always false if the password was incorrect.</param>
        /// <param name="newFormattedHash">If isUpdated is true, then newFormattedHash is the password hashed with the new cost parameters. If isUpdated is false, then newFormattedHash is expectedHash.</param>
        /// <returns>Whether the password results in the expectedHash when hashed</returns>
        /// </summary>
        bool VerifyAndUpdate(string expectedHash, string password, out bool isUpdated, out string newFormattedHash);

        /// <summary>
        /// Hashes the password and verifies that the password results in the specified hash. (See Verify method)
        /// If the password verification is successful, this method checks to see if the memory cost, time cost, and parallelism
        /// match the parameters the PasswordHasher object was constructed with. If they do not much, then the password is rehashed
        /// using the new parameters and the result is outputted via the newFormattedHash parameter.
        /// <param name="expectedHash">Hashing the password should result in this hash</param>
        /// <param name="password">The raw password bytes to hash and compare its result to expectedHash</param>
        /// <param name="isUpdated">Whether the cost parameters of expectedHash differ from the PasswordHasher object and if the password was rehashed using th new parameters. This is always false if the password was incorrect.</param>
        /// <param name="newFormattedHash">If isUpdated is true, then newFormattedHash is the password hashed with the new cost parameters. If isUpdated is false, then newFormattedHash is expectedHash.</param>
        /// <returns>Whether the password results in the expectedHash when hashed</returns>
        /// </summary>
        bool VerifyAndUpdate(string expectedHash, byte[] password, out bool isUpdated, out string newFormattedHash);

        #endregion
    }
}

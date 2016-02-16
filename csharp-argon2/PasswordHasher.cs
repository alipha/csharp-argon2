/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2016 Kevin Spinar (Alipha)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Liphsoft.Crypto.Argon2
{
    /// <summary>
    /// PasswordHasher is a class for creating Argon2 hashes and verifying them. This is a wrapper around
    /// Daniel Dinu and Dmitry Khovratovich's Argon2 library.
    /// </summary>
    public class PasswordHasher
    {
        #region Properties and Constructor

        private static readonly RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();

        private static readonly Regex HashRegex = new Regex(@"^\$argon2([di])\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/=]*)\$([A-Za-z0-9+/=]+)$", RegexOptions.Compiled);


        /// <summary>
        /// How many iterations of the Argon2 hash to perform
        /// </summary>
        public uint TimeCost { get; set; }

        /// <summary>
        /// How much memory to use while hashing in kibibytes (KiB)
        /// </summary>
        public uint MemoryCost { get; set; }

        /// <summary>
        /// How many threads to use while hashing
        /// </summary>
        public uint Parallelism { get; set; }

        /// <summary>
        /// The type of Argon2 hashing algorithm to use
        /// Argon2d - The memory access is dependent upon the hash value (vulnerable to side-channel attacks)
        /// Argon2i - The memory access is independent upon the hash value (safe from side-channel atacks)
        /// </summary>
        public Argon2Type ArgonType { get; set; }

        /// <summary>
        /// How strings should be decoded when passed to the Hash method.
        /// The default is Encoding.UTF8.
        /// </summary>
        public Encoding StringEncoding { get; set; }


        /// <summary>
        /// Initialize the Argon2 PasswordHasher with the performance and algorithm settings to use while hashing
        /// <param name="timeCost">How many iterations of the Argon2 hash to perform (default: 3, must be at least 1)</param>
        /// <param name="memoryCost">How much memory to use while hashing in kibibytes (KiB) (default: 65536 KiB [64 MiB], must be at least 8 KiB)</param>
        /// <param name="parallelism">How many threads to use while hashing (default: 1, must be at least 1)</param>
        /// <param name="argonType">The type of Argon2 hashing algorithm to use (Independent [default] or Dependent)</param>
        /// </summary>
        public PasswordHasher(uint timeCost = 3, uint memoryCost = 65536, uint parallelism = 1, Argon2Type argonType = Argon2Type.Argon2i)
        {
            TimeCost = timeCost;
            MemoryCost = memoryCost;
            Parallelism = parallelism;
            ArgonType = argonType;
            StringEncoding = Encoding.UTF8;
        }

        #endregion


        #region Hash Methods

        /// <summary>
        /// Hash the password using Argon2 with a cryptographically-secure, random, 16-byte salt.
        /// This is the only overload of the Hash method that the typical user will need to use. The other overloads are provided for interoperability purposes.
        /// Do not compare two Argon2 hashes directly. Instead, use the Verify or VerifyAndUpdate methods.
        /// The timing of this method may leak information about the length of the password and/or the character set.
        /// <param name="password">A string representing the password to be hashed. The password is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <returns>A formatted string representing the hashed password, encoded with the parameters used to perform the hash</returns>
        /// </summary>
        public string Hash(string password)
        {
            CheckNull("Hash", "password", password);

            return Hash(StringEncoding.GetBytes(password));
        }

        /// <summary>
        /// Hash the raw password bytes using Argon2 with a cryptographically-secure, random, 16-byte salt.
        /// Do not compare two Argon2 hashes directly. Instead, use the Verify or VerifyAndUpdate methods.
        /// <param name="password">The raw bytes of the password to be hashed</param>
        /// <returns>A formatted string representing the hashed password, encoded with the parameters used to perform the hash</returns>
        /// </summary>
        public string Hash(byte[] password)
        {
            CheckNull("Hash", "password", password);

            var salt = new byte[16];
            Rng.GetBytes(salt);
            return Hash(password, salt);
        }

        /// <summary>
        /// Hash the password using Argon2 with the specified salt.
        /// Unless you need to specify your own salt for interoperability purposes, prefer the Hash(string password) overload instead.
        /// Do not compare two Argon2 hashes directly. Instead, use the Verify or VerifyAndUpdate methods.
        /// The timing of this method may leak information about the length and/or character set of the password and salt.
        /// <param name="password">A string representing the password to be hashed. The password is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <param name="salt">A string representing the salt to be used for the hash. The salt must be at least 8 bytes. The salt is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <returns>A formatted string representing the hashed password, encoded with the parameters used to perform the hash</returns>
        /// </summary>
        public string Hash(string password, string salt)
        {
            CheckNull("Hash", "password", password, "salt", salt);

            return Hash(StringEncoding.GetBytes(password), StringEncoding.GetBytes(salt));
        }

        /// <summary>
        /// Hash the raw password bytes using Argon2 with the specified salt bytes.
        /// Unless you need to specify your own salt for interoperability purposes, prefer the Hash(byte[] password) overload instead.
        /// Do not compare two Argon2 hashes directly. Instead, use the Verify or VerifyAndUpdate methods.
        /// <param name="password">The raw bytes of the password to be hashed</param>
        /// <param name="salt">The raw salt bytes to be used for the hash. The salt must be at least 8 bytes.</param>
        /// <returns>A formatted string representing the hashed password, encoded with the parameters used to perform the hash</returns>
        /// </summary>
        public string Hash(byte[] password, byte[] salt)
        {
            CheckNull("Hash", "password", password, "salt", salt);

            var hash = new byte[32];
            var encoded = new byte[81 + (salt.Length * 4 + 3) / 3];
            var result = (Argon2Error)crypto_argon2_hash(TimeCost, MemoryCost, Parallelism, password, password.Length, salt, salt.Length, hash, hash.Length, encoded, encoded.Length, (int)ArgonType);

            if (result != Argon2Error.OK)
                throw new Argon2Exception("hashing", result);

            var firstNonNull = encoded.Length - 2;
            while (encoded[firstNonNull] == 0)
                firstNonNull--;

            return Encoding.ASCII.GetString(encoded, 0, firstNonNull + 1);
        }

        #endregion


        #region Verify Methods

        /// <summary>
        /// Hashes the password and verifies that the password results in the specified hash.
        /// The ArgonType must of this PasswordHasher object must match what was used to generate expectedHash.
        /// The other parameters (timeCost, etc.) do not need to match and the parameters embedded in the expectedHash will be used.
        /// The timing of this method may leak information about the length and/or character set of the attempted password.
        /// <param name="expectedHash">Hashing the password should result in this hash</param>
        /// <param name="password">The password to hash and compare its result to expectedHash. The password is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <returns>Whether the password results in the expectedHash when hashed</returns>
        /// </summary>
        public bool Verify(string expectedHash, string password)
        {
            CheckNull("Verify", "expectedHash", expectedHash, "password", password);

            return Verify(expectedHash, StringEncoding.GetBytes(password));
        }

        /// <summary>
        /// Hashes the raw password bytes and verifies that the password results in the specified hash.
        /// The ArgonType must of this PasswordHasher object must match what was used to generate expectedHash.
        /// The other parameters (timeCost, etc.) do not need to match and the parameters embedded in the expectedHash will be used.
        /// <param name="expectedHash">Hashing the password should result in this hash</param>
        /// <param name="password">The raw password bytes to hash and compare its result to expectedHash</param>
        /// <returns>Whether the password results in the expectedHash when hashed</returns>
        /// </summary>
        public bool Verify(string expectedHash, byte[] password)
        {
            CheckNull("Verify", "expectedHash", expectedHash, "password", password);

            var result = (Argon2Error)crypto_argon2_verify(StringEncoding.GetBytes(expectedHash), password, password.Length, (int)ArgonType);

            if (result == Argon2Error.OK || result == Argon2Error.DECODING_FAIL)
                return result == Argon2Error.OK;

            throw new Argon2Exception("verifying", result);
        }



        /// <summary>
        /// Hashes the password and verifies that the password results in the specified hash. (See Verify method)
        /// If the password verification is successful, this method checks to see if the memory cost, time cost, and parallelism
        /// match the parameters the PasswordHasher object was constructed with. If they do not much, then the password is rehashed
        /// using the new parameters and the result is outputted via the newFormattedHash parameter.
        /// If the verification is not successful, the timing of this method may leak information about the length and/or character set of the attempted password.
        /// If verification is successful, then the timing may leak information about the hash.
        /// <param name="expectedHash">Hashing the password should result in this hash</param>
        /// <param name="password">The password to hash and compare its result to expectedHash. The password is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <param name="isUpdated">Whether the cost parameters of expectedHash differ from the PasswordHasher object and if the password was rehashed using th new parameters. This is always false if the password was incorrect.</param>
        /// <param name="newFormattedHash">If isUpdated is true, then newFormattedHash is the password hashed with the new cost parameters. If isUpdated is false, then newFormattedHash is expectedHash.</param>
        /// <returns>Whether the password results in the expectedHash when hashed</returns>
        /// </summary>
        public bool VerifyAndUpdate(string expectedHash, string password, out bool isUpdated, out string newFormattedHash)
        {
            CheckNull("VerifyAndUpdate", "expectedHash", expectedHash, "password", password);

            return VerifyAndUpdate(expectedHash, StringEncoding.GetBytes(password), out isUpdated, out newFormattedHash);
        }

        /// <summary>
        /// Hashes the password and verifies that the password results in the specified hash. (See Verify method)
        /// If the password verification is successful, this method checks to see if the memory cost, time cost, and parallelism
        /// match the parameters the PasswordHasher object was constructed with. If they do not much, then the password is rehashed
        /// using the new parameters and the result is outputted via the newFormattedHash parameter.
        /// If the verification is not successful, this method operates in constant time.
        /// If verification is successful, then the timing may leak information about the hash.
        /// <param name="expectedHash">Hashing the password should result in this hash</param>
        /// <param name="password">The raw password bytes to hash and compare its result to expectedHash</param>
        /// <param name="isUpdated">Whether the cost parameters of expectedHash differ from the PasswordHasher object and if the password was rehashed using th new parameters. This is always false if the password was incorrect.</param>
        /// <param name="newFormattedHash">If isUpdated is true, then newFormattedHash is the password hashed with the new cost parameters. If isUpdated is false, then newFormattedHash is expectedHash.</param>
        /// <returns>Whether the password results in the expectedHash when hashed</returns>
        /// </summary>
        public bool VerifyAndUpdate(string expectedHash, byte[] password, out bool isUpdated, out string newFormattedHash)
        {
            CheckNull("VerifyAndUpdate", "expectedHash", expectedHash, "password", password);

            if (Verify(expectedHash, password))
            {
                var hashMetadata = ExtractMetadata(expectedHash);

                if (hashMetadata.MemoryCost != MemoryCost || hashMetadata.TimeCost != TimeCost || hashMetadata.Parallelism != Parallelism)
                {
                    isUpdated = true;
                    byte[] salt = hashMetadata.GetSaltBytes();
                    newFormattedHash = Hash(password, salt);
                }
                else
                {
                    isUpdated = false;
                    newFormattedHash = expectedHash;
                }

                return true;
            }

            isUpdated = false;
            newFormattedHash = expectedHash;
            return false;
        }

        #endregion


        #region Extract Metadata Method

        /// <summary>
        /// Extracts the memory cost, time cost, etc. used to generate the Argon2 hash.
        /// This method does not support all the features of Argon2 hash and will fail to decode hashes
        /// generated using the extra features not supported in this C# binding.
        /// This method does not operate in constant time and may leak information about the value of the hash.
        /// <param name="formattedHash">An encoded Argon2 hash created by the Hash method</param>
        /// <returns>The hash metadata or null if the formattedHash was not a valid encoded Argon2 hash</returns>
        /// </summary>
        public HashMetadata ExtractMetadata(string formattedHash)
        {
            CheckNull("ExtractMetadata", "formattedHash", formattedHash);

            var match = HashRegex.Match(formattedHash);

            if (!match.Success)
                return null;

            return new HashMetadata
            {
                ArgonType = (match.Groups[1].Value == "i" ? Argon2Type.Argon2i : Argon2Type.Argon2d),
                MemoryCost = uint.Parse(match.Groups[2].Value),
                TimeCost = uint.Parse(match.Groups[3].Value),
                Parallelism = uint.Parse(match.Groups[4].Value),
                Base64Salt = match.Groups[5].Value,
                Base64Hash = match.Groups[6].Value
            };
        }

        #endregion


        #region HashRaw Methods

        /// <summary>
        /// Hash the password using Argon2 with a cryptographically-secure, random, 16-byte salt.
        /// The HashRaw methods are provided for interoperability purposes. The Hash methods should be used in favor over the HashRaw methods. 
        /// The timing of this method may leak information about the length of the password and/or the character set.
        /// <param name="password">A string representing the password to be hashed. The password is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <returns>A 32-byte array containing only the resulting hash</returns>
        /// </summary>
        public byte[] HashRaw(string password)
        {
            CheckNull("HashRaw", "password", password);

            return HashRaw(StringEncoding.GetBytes(password));
        }

        /// <summary>
        /// Hash the raw password bytes using Argon2 with a cryptographically-secure, random, 16-byte salt.
        /// The HashRaw methods are provided for interoperability purposes. The Hash methods should be used in favor over the HashRaw methods. 
        /// <param name="password">The raw bytes of the password to be hashed</param>
        /// <returns>A 32-byte array containing only the resulting hash</returns>
        /// </summary>
        public byte[] HashRaw(byte[] password)
        {
            CheckNull("HashRaw", "password", password);

            var salt = new byte[16];
            Rng.GetBytes(salt);
            return HashRaw(password, salt);
        }

        /// <summary>
        /// Hash the password using Argon2 with the specified salt.
        /// The HashRaw methods are provided for interoperability purposes. The Hash methods should be used in favor over the HashRaw methods. 
        /// The timing of this method may leak information about the length and/or character set of the password and salt.
        /// <param name="password">A string representing the password to be hashed. The password is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <param name="salt">A string representing the salt to be used for the hash. The salt must be at least 8 bytes. The salt is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <returns>A 32-byte array containing only the resulting hash</returns>
        /// </summary>
        public byte[] HashRaw(string password, string salt)
        {
            CheckNull("HashRaw", "password", password, "salt", salt);

            return HashRaw(StringEncoding.GetBytes(password), StringEncoding.GetBytes(salt));
        }

        /// <summary>
        /// Hash the raw password bytes using Argon2 with the specified salt bytes.
        /// The HashRaw methods are provided for interoperability purposes. The Hash methods should be used in favor over the HashRaw methods. 
        /// <param name="password">The raw bytes of the password to be hashed</param>
        /// <param name="salt">The raw salt bytes to be used for the hash. The salt must be at least 8 bytes.</param>
        /// <returns>A 32-byte array containing only the resulting hash</returns>
        /// </summary>
        public byte[] HashRaw(byte[] password, byte[] salt)
        {
            CheckNull("HashRaw", "password", password, "salt", salt);

            var hash = new byte[32];
            var result = (Argon2Error)crypto_argon2_hash(TimeCost, MemoryCost, Parallelism, password, password.Length, salt, salt.Length, hash, hash.Length, null, 0, (int)ArgonType);

            if (result != Argon2Error.OK)
                throw new Argon2Exception("raw hashing", result);

            return hash;
        }

        #endregion


        #region Privates

        private static void CheckNull(string methodName, params object[] arguments)
        {
            for (var i = 0; i < arguments.Length; i += 2)
                if (arguments[i + 1] == null)
                    throw new ArgumentNullException(arguments[i].ToString(), string.Format("Argument {0} to method PasswordHasher.{1} is null", arguments[i], methodName));
        }

        [DllImport("libargon2.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int crypto_argon2_hash(uint t_cost, uint m_cost, uint parallelism,
            byte[] pwd, int pwdlen,
            byte[] salt, int saltlen,
            byte[] hash, int hashlen,
            byte[] encoded, int encodedlen,
            int type);

        [DllImport("libargon2.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int crypto_argon2_verify(byte[] encoded, byte[] pwd, int pwdlen, int type);

        #endregion
    }
}
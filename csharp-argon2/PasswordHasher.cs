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
    public class PasswordHasher : IPasswordHasher
    {
        #region Properties and Constructor

        private static readonly RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();


        /// <summary>
        /// Which Argon2 version this PasswordHasher class uses
        /// </summary>
        public static int Argon2Version { get { return 0x13;  } }

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
        /// Length of the generated raw hash in bytes
        /// </summary>
        public uint HashLength { get; set; }

        /// <summary>
        /// How strings should be decoded when passed to the Hash method.
        /// The default is Encoding.UTF8.
        /// </summary>
        public Encoding StringEncoding { get; set; }


        /// <summary>
        /// Initialize the Argon2 PasswordHasher with default performance and algorithm settings based upon the environment the hashing will be used in.
        /// You should perform your own profiling to determine what the parameters should be for your specific usage; however, this attempts to provide
        /// some reasonable defaults.
        /// <param name="environment">Whether the PasswordHasher will be used in a server or single-user setting</param>
        /// </summary>
        public PasswordHasher(UsageEnvironment environment)
        {
            switch (environment)
            {
                case UsageEnvironment.Server:
                    TimeCost = 3;
                    MemoryCost = 8192;
                    Parallelism = 1;
                    break;
                case UsageEnvironment.SingleUser:
                    TimeCost = 10;
                    MemoryCost = 131072;
                    Parallelism = 2;
                    break;
            }

            ArgonType = Argon2Type.Argon2i;
            HashLength = 32;
            StringEncoding = Encoding.UTF8;
        }


        /// <summary>
        /// Initialize the Argon2 PasswordHasher with the performance and algorithm settings to use while hashing
        /// <param name="timeCost">How many iterations of the Argon2 hash to perform (default: 3, must be at least 1)</param>
        /// <param name="memoryCost">How much memory to use while hashing in kibibytes (KiB) (default: 8192 KiB [8 MiB], must be at least 8 KiB)</param>
        /// <param name="parallelism">How many threads to use while hashing (default: 1, must be at least 1)</param>
        /// <param name="argonType">The type of Argon2 hashing algorithm to use (Independent [default] or Dependent)</param>
        /// <param name="hashLength">The length of the resulting hash in bytes (default: 32)</param>
        /// </summary>
        public PasswordHasher(uint timeCost = 3, uint memoryCost = 8192, uint parallelism = 1, Argon2Type argonType = Argon2Type.Argon2i, uint hashLength = 32)
        {
            TimeCost = timeCost;
            MemoryCost = memoryCost;
            Parallelism = parallelism;
            ArgonType = argonType;
            HashLength = hashLength;
            StringEncoding = Encoding.UTF8;
        }

        #endregion


        #region Hash Methods

        /// <summary>
        /// Hash the password using Argon2 with a cryptographically-secure, random, 16-byte salt.
        /// This is the only overload of the Hash method that the typical user will need to use for password storage. The other overloads are provided for interoperability purposes.
        /// Do not compare two Argon2 hashes directly. Instead, use the Verify or VerifyAndUpdate methods.
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

            return Hash(password, GenerateSalt());
        }

        /// <summary>
        /// Hash the password using Argon2 with the specified salt.
        /// Unless you need to specify your own salt for interoperability purposes, prefer the Hash(string password) overload instead.
        /// Do not compare two Argon2 hashes directly. Instead, use the Verify or VerifyAndUpdate methods.
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
        /// Hash the password using Argon2 with the specified salt.
        /// Unless you need to specify your own salt for interoperability purposes, prefer the Hash(string password) overload instead.
        /// Do not compare two Argon2 hashes directly. Instead, use the Verify or VerifyAndUpdate methods.
        /// <param name="password">he raw bytes of the password to be hashed</param>
        /// <param name="salt">A string representing the salt to be used for the hash. The salt must be at least 8 bytes. The salt is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <returns>A formatted string representing the hashed password, encoded with the parameters used to perform the hash</returns>
        /// </summary>
        public string Hash(byte[] password, string salt)
        {
            CheckNull("Hash", "password", password, "salt", salt);

            return Hash(password, StringEncoding.GetBytes(salt));
        }

        /// <summary>
        /// Hash the password using Argon2 with the specified salt.
        /// Unless you need to specify your own salt for interoperability purposes, prefer the Hash(string password) overload instead.
        /// Do not compare two Argon2 hashes directly. Instead, use the Verify or VerifyAndUpdate methods.
        /// <param name="password">A string representing the password to be hashed. The password is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <param name="salt">The raw salt bytes to be used for the hash. The salt must be at least 8 bytes.</param>
        /// <returns>A formatted string representing the hashed password, encoded with the parameters used to perform the hash</returns>
        /// </summary>
        public string Hash(string password, byte[] salt)
        {
            CheckNull("Hash", "password", password, "salt", salt);

            return Hash(StringEncoding.GetBytes(password), salt);
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

            var hash = new byte[HashLength];
            var encodedLength = GetEncodedHashLength(HashLength, (uint) salt.Length);
            var encoded = new byte[encodedLength];

            var result = (Argon2Error)crypto_argon2_hash(TimeCost, MemoryCost, Parallelism, password, password.Length, 
                salt, salt.Length, hash, hash.Length, encoded, encoded.Length, (int)ArgonType, Argon2Version);

            if (result != Argon2Error.OK)
                throw new Argon2Exception("hashing", result);

            var firstNonNull = encoded.Length - 2;
            while (encoded[firstNonNull] == 0)
                firstNonNull--;

            return Encoding.ASCII.GetString(encoded, 0, firstNonNull + 1);
        }

        #endregion


        #region GenerateKey and ReproduceKey Methods

        /// <summary>
        /// Hash the password using Argon2 with a randomly-generated salt in order to generate a key. 
        /// The salt and algorithm parameters (time cost, etc.) are encoded and returned through the keyMetadata out argument.
        /// If you wish to generate a key using an already-provided salt and algorithm parameters, use the ReproduceKey method.
        /// You can use PasswordHasher.DecodeMetadata to analyze the resulting keyMetadata.
        /// For password storage, use the Hash methods instead. 
        /// The ArgonType in the keyMetadata must match the ArgonType of this PasswordHasher object.
        /// <param name="password">A string representing the password to be hashed in order to create a key. The password is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <param name="keyMetadata">An encoded string of the salt, ArgonType, time cost, and other parameters that were used to create the key.</param>
        /// <returns>A byte array containing only the resulting key</returns>
        /// </summary>
        public byte[] GenerateKey(string password, out string keyMetadata)
        {
            return GenerateKey(StringEncoding.GetBytes(password), out keyMetadata);
        }

        /// <summary>
        /// Hash the password using Argon2 with a randomly-generated salt in order to generate a key. 
        /// The salt and algorithm parameters (time cost, etc.) are encoded and returned through the keyMetadata out argument.
        /// If you wish to generate a key using an already-provided salt and algorithm parameters, use the ReproduceKey method.
        /// You can use PasswordHasher.DecodeMetadata to analyze the resulting keyMetadata.
        /// For password storage, use the Hash methods instead. 
        /// The ArgonType in the keyMetadata must match the ArgonType of this PasswordHasher object.
        /// <param name="password">The raw bytes of the password to be hashed in order to create a key</param>
        /// <param name="keyMetadata">An encoded string of the salt, ArgonType, time cost, and other parameters that were used to create the key.</param>
        /// <returns>A byte array containing only the resulting key</returns>
        /// </summary>
        public byte[] GenerateKey(byte[] password, out string keyMetadata)
        {
            var hashMetadata = new HashMetadata
            {
                ArgonType = ArgonType,
                MemoryCost = MemoryCost,
                TimeCost = TimeCost,
                Parallelism = Parallelism,
                Salt = GenerateSalt(),
                Hash = new byte[4]

            };

            var metadata = hashMetadata.Encode();
            keyMetadata = metadata.Substring(0, metadata.Length - 6);

            var hash = new byte[HashLength];
            var result = (Argon2Error)crypto_argon2_hash(TimeCost, MemoryCost, Parallelism, password, password.Length, 
                hashMetadata.Salt, hashMetadata.Salt.Length, hash, hash.Length, null, 0, (int)ArgonType, Argon2Version);

            if (result != Argon2Error.OK)
                throw new Argon2Exception("reproducing key", result);

            return hash;
        }

        /// <summary>
        /// Hash the password using Argon2 with the specified metadata in order to generate a key. Typically, one would use GenerateKey to create
        /// a key with a random salt, then use ReproduceKey to recreate the same key.
        /// If you do not have an encoded metadata string from GenerateKey, you can use PasswordHasher.EncodeMetadata to create one.
        /// For password storage, use the Hash methods instead. 
        /// The ArgonType in the keyMetadata must match the ArgonType of this PasswordHasher object.
        /// <param name="password">A string representing the password to be hashed in order to create a key. The password is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <param name="keyMetadata">An encoded string of the salt, ArgonType, time cost, and other parameters to use to recreate the key.</param>
        /// <returns>A byte array containing only the resulting key</returns>
        /// </summary>
        public byte[] ReproduceKey(string password, string keyMetadata)
        {
            return ReproduceKey(StringEncoding.GetBytes(password), keyMetadata);
        }

        /// <summary>
        /// Hash the password using Argon2 with the specified metadata in order to generate a key. Typically, one would use GenerateKey to create
        /// a key with a random salt, then use ReproduceKey to recreate the same key.
        /// For password storage, use the Hash methods instead. 
        /// The ArgonType in the keyMetadata must match the ArgonType of this PasswordHasher object.
        /// <param name="password">The raw bytes of the password to be hashed in order to create a key</param>
        /// <param name="keyMetadata">An encoded string of the salt, ArgonType, time cost, and other parameters to use to recreate the key.</param>
        /// <returns>A byte array containing only the resulting key</returns>
        /// </summary>
        public byte[] ReproduceKey(byte[] password, string keyMetadata)
        {
            keyMetadata = keyMetadata.Trim();
            var hashMetadata = DecodeMetadata(keyMetadata + (keyMetadata.EndsWith("$") ? "AAAAAA" : ""));

            if (hashMetadata.ArgonType != ArgonType)
                throw new Argon2TypeMismatchException("reproducing key");

            var hash = new byte[HashLength];
            var result = (Argon2Error)crypto_argon2_hash(hashMetadata.TimeCost, hashMetadata.MemoryCost, hashMetadata.Parallelism, password, password.Length, 
                hashMetadata.Salt, hashMetadata.Salt.Length, hash, hash.Length, null, 0, (int)ArgonType, Argon2Version);

            if (result != Argon2Error.OK)
                throw new Argon2Exception("reproducing key", result);

            return hash;
        }

        #endregion


        #region HashRaw Methods

        /// <summary>
        /// Hash the password using Argon2 with the specified salt.
        /// Unless you're using HashRaw for interoperability purposes, the Hash methods should be used in favor of the HashRaw methods. 
        /// If you wish to perform key generation, use GenerateKey and ReproduceKey.
        /// <param name="password">A string representing the password to be hashed. The password is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <param name="salt">A string representing the salt to be used for the hash. The salt must be at least 8 bytes. The salt is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <returns>A byte array containing only the resulting hash</returns>
        /// </summary>
        public byte[] HashRaw(string password, string salt)
        {
            CheckNull("HashRaw", "password", password, "salt", salt);

            return HashRaw(StringEncoding.GetBytes(password), StringEncoding.GetBytes(salt));
        }

        /// <summary>
        /// Hash the password using Argon2 with the specified salt.
        /// Unless you're using HashRaw for interoperability purposes, the Hash methods should be used in favor of the HashRaw methods. 
        /// If you wish to perform key generation, use GenerateKey and ReproduceKey.
        /// <param name="password">The raw bytes of the password to be hashed</param>
        /// <param name="salt">A string representing the salt to be used for the hash. The salt must be at least 8 bytes. The salt is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <returns>A byte array containing only the resulting hash</returns>
        /// </summary>
        public byte[] HashRaw(byte[] password, string salt)
        {
            CheckNull("HashRaw", "password", password, "salt", salt);

            return HashRaw(password, StringEncoding.GetBytes(salt));
        }

        /// <summary>
        /// Hash the password using Argon2 with the specified salt. The HashRaw methods may be used for password-based key derivation.
        /// Unless you're using HashRaw for key deriviation or for interoperability purposes, the Hash methods should be used in favor of the HashRaw methods. 
        /// <param name="password">A string representing the password to be hashed. The password is first decoded into bytes using StringEncoding (default: Encoding.UTF8)</param>
        /// <param name="salt">The raw salt bytes to be used for the hash. The salt must be at least 8 bytes.</param>
        /// <returns>A byte array containing only the resulting hash</returns>
        /// </summary>
        public byte[] HashRaw(string password, byte[] salt)
        {
            CheckNull("HashRaw", "password", password, "salt", salt);

            return HashRaw(StringEncoding.GetBytes(password), salt);
        }

        /// <summary>
        /// Hash the password using Argon2 with the specified salt. The HashRaw methods may be used for password-based key derivation.
        /// Unless you're using HashRaw for key deriviation or for interoperability purposes, the Hash methods should be used in favor of the HashRaw methods.
        /// <param name="password">The raw bytes of the password to be hashed</param>
        /// <param name="salt">The raw salt bytes to be used for the hash. The salt must be at least 8 bytes.</param>
        /// <returns>A byte array containing only the resulting hash</returns>
        /// </summary>
        public byte[] HashRaw(byte[] password, byte[] salt)
        {
            CheckNull("HashRaw", "password", password, "salt", salt);

            var hash = new byte[HashLength];
            var result = (Argon2Error)crypto_argon2_hash(TimeCost, MemoryCost, Parallelism, password, password.Length, 
                salt, salt.Length, hash, hash.Length, null, 0, (int)ArgonType, Argon2Version);

            if (result != Argon2Error.OK)
                throw new Argon2Exception("raw hashing", result);

            return hash;
        }

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
                var hashMetadata = DecodeMetadata(expectedHash, throwOnError: false);

                if (hashMetadata.MemoryCost != MemoryCost || hashMetadata.TimeCost != TimeCost || hashMetadata.Parallelism != Parallelism)
                {
                    isUpdated = true;
                    byte[] salt = hashMetadata.Salt;
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


        #region Utility Methods

        /// <summary>
        /// Generate salt using a Cryptographically-Secure Pseudo-Random Number Generator
        /// <param name="byteLength">The number of bytes of salt to generate (default: 16)</param>
        /// <returns>A array of randomly-generated bytes</returns>
        /// </summary>
        public static byte[] GenerateSalt(uint byteLength = 16)
        {
            var salt = new byte[byteLength];
            Rng.GetBytes(salt);
            return salt;
        }

        /// <summary>
        /// Determine the maximum number of bytes needed to store the encoded hash with its metadata (type, salt, time cost, etc.)
        /// </summary>
        /// <param name="hashLength">The length of the hash to be stored, in bytes</param>
        /// <param name="saltLength">The length of the salt to be stored, in bytes</param>
        /// <returns>The maximum number of bytes needed to store the encoded hash with its metadata</returns>
        public static uint GetEncodedHashLength(uint hashLength, uint saltLength)
        {
            return 45 + ((hashLength + saltLength) * 4 + 3) / 3;
        }


        /// <summary>
        /// Extracts the memory cost, time cost, etc. used to generate the Argon2 hash.
        /// <param name="formattedHash">An encoded Argon2 hash created by the Hash method</param>
        /// <param name="throwOnError">Whether to throw on an error so you can get detailed error information or to simply return null</param>
        /// <returns>The hash metadata if the formattedHash was a valid encoded Argon2 hash, else throws or returns null</returns>
        /// </summary>
        public static HashMetadata DecodeMetadata(string formattedHash, bool throwOnError = true)
        {
            CheckNull("ExtractMetadata", "formattedHash", formattedHash);

            var context = new Argon2Context
            {
                OutLen = (uint)formattedHash.Length,
                SaltLen = (uint)formattedHash.Length
            };

            try
            {
                context.Out = Marshal.AllocHGlobal(formattedHash.Length);  // a little more space than we need, but probably not worth computing the exact amount
                context.Salt = Marshal.AllocHGlobal(formattedHash.Length);

                var type = GetArgonType(formattedHash);
                var result = (Argon2Error)crypto_decode_string(context, Encoding.ASCII.GetBytes(formattedHash + "\0"), (int)type);

                if (result != Argon2Error.OK)
                {
                    if (throwOnError)
                        throw new Argon2Exception("decoding", result);
                    return null;
                }

                var salt = new byte[context.SaltLen];
                var hash = new byte[context.OutLen];
                Marshal.Copy(context.Salt, salt, 0, salt.Length);
                Marshal.Copy(context.Out, hash, 0, hash.Length);

                return new HashMetadata
                {
                    ArgonType = type,
                    MemoryCost = context.MemoryCost,
                    TimeCost = context.TimeCost,
                    Parallelism = context.Threads,
                    Salt = salt,
                    Hash = hash
                };
            }
            finally
            {
                try
                {
                    Marshal.FreeHGlobal(context.Out);
                }
                finally
                {
                    Marshal.FreeHGlobal(context.Salt);
                }
            }
        }


        /// <summary>
        /// Generates an encoded string of the metadata for the Argon2 hash.
        /// <param name="metadata">The Argon2 metadata</param>
        /// <param name="throwOnError">Whether to throw on an error so you can get detailed error information or to simply return null</param>
        /// <returns>The formatted hash if the Argon2 metadata was valid, else throws or returns null</returns>
        /// </summary>
        public static string EncodeMetadata(HashMetadata metadata, bool throwOnError = true)
        {
            CheckNull("ExtractMetadata", "metadata", metadata);

            var encodedLength = GetEncodedHashLength((uint)metadata.Hash.Length, (uint)metadata.Salt.Length);
            var encoded = new byte[encodedLength];

            var context = new Argon2Context
            {
                OutLen = (uint)metadata.Hash.Length,
                SaltLen = (uint)metadata.Salt.Length,
                TimeCost = metadata.TimeCost,
                MemoryCost = metadata.MemoryCost,
                Lanes = 1,
                Threads = metadata.Parallelism,
                Version = (uint)Argon2Version
            };

            try
            {
                context.Out = Marshal.AllocHGlobal(metadata.Hash.Length);
                context.Salt = Marshal.AllocHGlobal(metadata.Salt.Length);

                Marshal.Copy(metadata.Salt, 0, context.Salt, metadata.Salt.Length);
                Marshal.Copy(metadata.Hash, 0, context.Out, metadata.Hash.Length);

                var result = (Argon2Error)crypto_encode_string(encoded, encodedLength, context, (int)metadata.ArgonType);

                if (result != Argon2Error.OK)
                {
                    if (throwOnError)
                        throw new Argon2Exception("encoding", result);
                    return null;
                }
            
                var firstNonNull = encoded.Length - 2;
                while (encoded[firstNonNull] == 0)
                    firstNonNull--;

                return Encoding.ASCII.GetString(encoded, 0, firstNonNull + 1);
            }
            finally
            {
                try
                {
                    Marshal.FreeHGlobal(context.Out);
                }
                finally
                {
                    Marshal.FreeHGlobal(context.Salt);
                }
            }
        }

        #endregion


        #region Privates

        private static void CheckNull(string methodName, params object[] arguments)
        {
            for (var i = 0; i < arguments.Length; i += 2)
                if (arguments[i + 1] == null)
                    throw new ArgumentNullException(arguments[i].ToString(), string.Format("Argument {0} to method PasswordHasher.{1} is null", arguments[i], methodName));
        }

        private static Argon2Type GetArgonType(string formattedHash)
        {
            return formattedHash.StartsWith("$argon2d") ? Argon2Type.Argon2d : Argon2Type.Argon2i;
        }


        [DllImport("libargon2.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int crypto_argon2_hash(uint t_cost, uint m_cost, uint parallelism,
            byte[] pwd, int pwdlen,
            byte[] salt, int saltlen,
            byte[] hash, int hashlen,
            byte[] encoded, int encodedlen,
            int type, int version);


        [DllImport("libargon2.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int crypto_argon2_verify(byte[] encoded, byte[] pwd, int pwdlen, int type);


        [DllImport("libargon2.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int crypto_decode_string(Argon2Context ctx, byte[] str, int type);


        [DllImport("libargon2.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int crypto_encode_string(byte[] dst, uint dst_len, Argon2Context ctx, int type);

        #endregion
    }
}
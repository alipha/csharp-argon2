/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2016 Kevin Spinar
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
    /// 
    /// </summary>
    public class PasswordHasher
    {
        #region Properties and Constructor

        private static readonly RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();

        private static readonly Regex HashRegex = new Regex(@"^\$argon2([di])\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/=]*)\$([A-Za-z0-9+/=]+)$", RegexOptions.Compiled);


        /// <summary>
        /// 
        /// </summary>
        public int TimeCost { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public int MemoryCost { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public int Parallelism { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public Argon2Type ArgonType { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public Encoding StringEncoding { get; set; }


        /// <summary>
        /// 
        /// <param name="timeCost"></param>
        /// <param name="memoryCost"></param>
        /// <param name="parallelism"></param>
        /// <param name="argonType"></param>
        /// </summary>
        public PasswordHasher(int timeCost = 3, int memoryCost = 65536, int parallelism = 1, Argon2Type argonType = Argon2Type.Argon2i)
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
        /// 
        /// <param name="password"></param>
        /// <returns></returns>
        /// </summary>
        public string Hash(string password)
        {
            CheckNull("Hash", "password", password);

            return Hash(StringEncoding.GetBytes(password));
        }

        /// <summary>
        /// 
        /// <param name="password"></param>
        /// <returns></returns>
        /// </summary>
        public string Hash(byte[] password)
        {
            CheckNull("Hash", "password", password);

            var salt = new byte[16];
            Rng.GetBytes(salt);
            return Hash(password, salt);
        }

        /// <summary>
        /// 
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        /// </summary>
        public string Hash(string password, string salt)
        {
            CheckNull("Hash", "password", password, "salt", salt);

            return Hash(StringEncoding.GetBytes(password), StringEncoding.GetBytes(salt));
        }

        /// <summary>
        /// 
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
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
            while(encoded[firstNonNull] == 0)
                firstNonNull--;

            return Encoding.ASCII.GetString(encoded, 0, firstNonNull + 1);
        }

        #endregion


        #region Verify Methods

        /// <summary>
        /// 
        /// <param name="expectedHash"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        /// </summary>
        public bool Verify(string expectedHash, string password)
        {
            CheckNull("Verify", "expectedHash", expectedHash, "password", password);

            return Verify(expectedHash, StringEncoding.GetBytes(password));
        }

        /// <summary>
        /// 
        /// <param name="expectedHash"></param>
        /// <param name="password"></param>
        /// <returns></returns>
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
        /// 
        /// <param name="expectedHash"></param>
        /// <param name="password"></param>
        /// <param name="isUpdated"></param>
        /// <param name="newFormattedHash"></param>
        /// <returns></returns>
        /// </summary>
        public bool VerifyAndUpdate(string expectedHash, string password, out bool isUpdated, out string newFormattedHash)
        {
            CheckNull("VerifyAndUpdate", "expectedHash", expectedHash, "password", password);

            return VerifyAndUpdate(expectedHash, StringEncoding.GetBytes(password), out isUpdated, out newFormattedHash);
        }

        /// <summary>
        /// 
        /// <param name="expectedHash"></param>
        /// <param name="password"></param>
        /// <param name="isUpdated"></param>
        /// <param name="newFormattedHash"></param>
        /// <returns></returns>
        /// </summary>
        public bool VerifyAndUpdate(string expectedHash, byte[] password, out bool isUpdated, out string newFormattedHash)
        {
            CheckNull("VerifyAndUpdate", "expectedHash", expectedHash, "password", password);
            
            if (Verify(expectedHash, password))
            {
                var hashMetadata = ExtractMetadata(expectedHash);
                byte[] salt = hashMetadata.GetSaltBytes();

                if (hashMetadata.MemoryCost != MemoryCost || hashMetadata.TimeCost != TimeCost || hashMetadata.Parallelism != Parallelism)
                {
                    isUpdated = true;
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
        /// 
        /// <param name="formattedHash"></param>
        /// <returns></returns>
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
                MemoryCost = int.Parse(match.Groups[2].Value),
                TimeCost = int.Parse(match.Groups[3].Value),
                Parallelism = int.Parse(match.Groups[4].Value),
                Base64Salt = match.Groups[5].Value,
                Base64Hash = match.Groups[6].Value
            };
        }

        #endregion


        #region HashRaw Methods

        /// <summary>
        /// 
        /// <param name="password"></param>
        /// <returns></returns>
        /// </summary>
        public byte[] HashRaw(string password)
        {
            CheckNull("HashRaw", "password", password);
            
            return HashRaw(StringEncoding.GetBytes(password));
        }

        /// <summary>
        /// 
        /// <param name="password"></param>
        /// <returns></returns>
        /// </summary>
        public byte[] HashRaw(byte[] password)
        {
            CheckNull("HashRaw", "password", password);
            
            var salt = new byte[16];
            Rng.GetBytes(salt);
            return HashRaw(password, salt);
        }

        /// <summary>
        /// 
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        /// </summary>
        public byte[] HashRaw(string password, string salt)
        {
            CheckNull("HashRaw", "password", password, "salt", salt);

            return HashRaw(StringEncoding.GetBytes(password), StringEncoding.GetBytes(salt));
        }

        /// <summary>
        /// 
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
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
            for(var i = 0; i < arguments.Length; i += 2)
                if(arguments[i + 1] == null)
                    throw new ArgumentNullException(arguments[i].ToString(), string.Format("Argument {0} to method PasswordHasher.{1} is null", arguments[i], methodName));
        }

        [DllImport("libargon2.dll", CallingConvention=CallingConvention.Cdecl)]
        private static extern int crypto_argon2_hash(int t_cost, int m_cost, int parallelism, 
            byte[] pwd, int pwdlen, 
            byte[] salt, int saltlen, 
            byte[] hash, int hashlen, 
            byte[] encoded, int encodedlen, 
            int type);

        [DllImport("libargon2.dll", CallingConvention=CallingConvention.Cdecl)]
        private static extern int crypto_argon2_verify(byte[] encoded, byte[] pwd, int pwdlen, int type);

        #endregion
    }
}

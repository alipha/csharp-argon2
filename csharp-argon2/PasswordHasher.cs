using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Argon2
{
    public class PasswordHasher     // TODO: check null arguments
    {
        #region Properties and Constructor

        private static RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();

        private static Regex HashRegex = new Regex(@"$\$argon2([di])$m=(\d+),t=(\d+),p=(\d+)$([A-Za-z0-9+/=]*)$([A-Za-z0-9+/=]+)", RegexOptions.Compiled);

        
        public int TimeCost { get; set; }

        public int MemoryCost { get; set; }

        public int Parallelism { get; set; }

        public Argon2Type ArgonType { get; set; }

        public Encoding StringEncoding { get; set; }


        public PasswordHasher(int timeCost = 3, int memoryCost = 16, int parallelism = 1, Argon2Type argonType = Argon2Type.Argon2i)
        {
            TimeCost = timeCost;
            MemoryCost = 1 << memoryCost;
            Parallelism = parallelism;
            ArgonType = argonType;
            StringEncoding = Encoding.UTF8;
        }

        #endregion


        #region Hash Methods

        public string Hash(string password)
        {
            return Hash(StringEncoding.GetBytes(password));
        }

        public string Hash(byte[] password)
        {
            var salt = new byte[16];
            Rng.GetBytes(salt);
            return Hash(password, salt);
        }

        public string Hash(string password, string salt)
        {
            return Hash(StringEncoding.GetBytes(password), StringEncoding.GetBytes(salt));
        }

        public string Hash(byte[] password, byte[] salt)
        {
            var hash = new byte[32];
            var encoded = new byte[81 + (salt.Length * 4 + 3) / 3];
            var result = (Argon2Error)crypto_argon2_hash(TimeCost, MemoryCost, Parallelism, password, password.Length, salt, salt.Length, hash, hash.Length, encoded, encoded.Length, (int)ArgonType);

            if (result != Argon2Error.OK)
                throw new Argon2Exception("hashing", result);

            var firstNonNull = encoded.Length - 2;
            while(encoded[firstNonNull] == 0)
                firstNonNull--;

            return StringEncoding.GetString(encoded, 0, firstNonNull + 1);
        }

        #endregion


        #region Verify Methods

        public bool Verify(string formattedHash, string password)
        {
            return Verify(formattedHash, StringEncoding.GetBytes(password));
        }

        public bool Verify(string formattedHash, byte[] password)
        {
            var result = (Argon2Error)crypto_argon2_verify(StringEncoding.GetBytes(formattedHash), password, password.Length, (int)ArgonType);

            if (result == Argon2Error.OK || result == Argon2Error.DECODING_FAIL)
                return result == Argon2Error.OK;

            throw new Argon2Exception("verifying", result);
        }


        public bool VerifyAndUpdate(string formattedHash, string password, out bool isUpdated, out string newFormattedHash)
        {
            return VerifyAndUpdate(formattedHash, StringEncoding.GetBytes(password), out isUpdated, out newFormattedHash);
        }

        public bool VerifyAndUpdate(string formattedHash, byte[] password, out bool isUpdated, out string newFormattedHash)
        {
            var hashMetadata = ExtractMetadata(formattedHash);
            byte[] salt = hashMetadata.GetSaltBytes();

            if (Verify(formattedHash, password))
            {
                isUpdated = (hashMetadata.MemoryCost != MemoryCost || hashMetadata.TimeCost != TimeCost || hashMetadata.Parallelism != Parallelism);

                if(isUpdated)
                    newFormattedHash = Hash(password, salt);
                else
                    newFormattedHash = formattedHash;

                return true;
            }

            isUpdated = false;
            newFormattedHash = formattedHash;
            return false;
        }

        #endregion


        #region Extract Metadata Method

        public HashMetadata ExtractMetadata(string formattedHash)
        {
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

        public byte[] HashRaw(string password)
        {
            return HashRaw(StringEncoding.GetBytes(password));
        }

        public byte[] HashRaw(byte[] password)
        {
            var salt = new byte[16];
            Rng.GetBytes(salt);
            return HashRaw(password, salt);
        }

        public byte[] HashRaw(string password, string salt)
        {
            return HashRaw(StringEncoding.GetBytes(password), StringEncoding.GetBytes(salt));
        }

        public byte[] HashRaw(byte[] password, byte[] salt)
        {
            var hash = new byte[32];
            var result = (Argon2Error)crypto_argon2_hash(TimeCost, MemoryCost, Parallelism, password, password.Length, salt, salt.Length, hash, hash.Length, null, 0, (int)ArgonType);

            if (result != Argon2Error.OK)
                throw new Argon2Exception("raw hashing", result);

            return hash;
        }

        #endregion


        #region Privates

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

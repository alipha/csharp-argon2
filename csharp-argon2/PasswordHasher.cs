using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Argon2
{
    public class PasswordHasher
    {
        private static RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();

        public int TimeCost { get; set; }

        public int MemoryCost { get; set; }

        public int Parallelism { get; set; }

        public Argon2Type ArgonType { get; set; }


        public PasswordHasher(int timeCost = 3, int memoryCost = 16, int parallelism = 1, Argon2Type argonType = Argon2Type.Argon2i)
        {
            TimeCost = timeCost;
            MemoryCost = 1 << memoryCost;
            Parallelism = parallelism;
            ArgonType = argonType;
        }


        public string Hash(string password)
        {
            return Hash(Encoding.UTF8.GetBytes(password));
        }

        public string Hash(byte[] password)
        {
            var salt = new byte[16];
            Rng.GetBytes(salt);
            return Hash(password, salt);
        }

        public string Hash(string password, string salt)
        {
            return Hash(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(salt));
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

            return Encoding.UTF8.GetString(encoded, 0, firstNonNull + 1);
        }


        public bool Verify(string encoded, string password)
        {
            return Verify(encoded, Encoding.UTF8.GetBytes(password));
        }

        public bool Verify(string encoded, byte[] password)
        {
            var result = (Argon2Error)crypto_argon2_verify(Encoding.UTF8.GetBytes(encoded), password, password.Length, (int)ArgonType);

            if (result == Argon2Error.OK || result == Argon2Error.DECODING_FAIL)
                return result == Argon2Error.OK;

            throw new Argon2Exception("verifying", result);
        }


        public byte[] HashRaw(string password)
        {
            return HashRaw(Encoding.UTF8.GetBytes(password));
        }

        public byte[] HashRaw(byte[] password)
        {
            var salt = new byte[16];
            Rng.GetBytes(salt);
            return HashRaw(password, salt);
        }

        public byte[] HashRaw(string password, string salt)
        {
            return HashRaw(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(salt));
        }

        public byte[] HashRaw(byte[] password, byte[] salt)
        {
            var hash = new byte[32];
            var result = (Argon2Error)crypto_argon2_hash(TimeCost, MemoryCost, Parallelism, password, password.Length, salt, salt.Length, hash, hash.Length, null, 0, (int)ArgonType);

            if (result != Argon2Error.OK)
                throw new Argon2Exception("raw hashing", result);

            return hash;
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
    }
}

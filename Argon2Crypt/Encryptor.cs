using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Liphsoft.Crypto
{
    public class Encryptor
    {
        public const int AesKeyByteSize = 32;
        public const int HmacKeyByteSize = 64;

        public byte[] AesKey { get; set; }

        public byte[] HmacKey { get; set; }

        public Encoding StringEncoding { get; set; }


        public Encryptor()
        {
            using (var aes = new RijndaelManaged())
            {
                aes.GenerateKey();
                AesKey = aes.Key;
            }

            using (var hmac = new HMACSHA256())
            {
                HmacKey = hmac.Key;
            }

            StringEncoding = Encoding.UTF8;
        }


        public Encryptor(string aesHmacKey)
        {
            var combinedKeyBytes = Convert.FromBase64String(aesHmacKey);
            AesKey = new byte[AesKeyByteSize];
            HmacKey = new byte[HmacKeyByteSize];

            Buffer.BlockCopy(combinedKeyBytes, 0, AesKey, 0, AesKeyByteSize);
            Buffer.BlockCopy(combinedKeyBytes, AesKeyByteSize, HmacKey, 0, HmacKeyByteSize);
            StringEncoding = Encoding.UTF8;
        }


        public Encryptor(byte[] aesKey, byte[] hmacKey)
        {
            AesKey = aesKey;
            HmacKey = hmacKey;
            StringEncoding = Encoding.UTF8;
        }


        public string Key()
        {
            var combinedKeyBytes = new byte[AesKeyByteSize + HmacKeyByteSize];
            Buffer.BlockCopy(AesKey, 0, combinedKeyBytes, 0, AesKeyByteSize);
            Buffer.BlockCopy(HmacKey, 0, combinedKeyBytes, AesKeyByteSize, HmacKeyByteSize);

            return Convert.ToBase64String(combinedKeyBytes);
        }


        public string Encrypt(string plaintext, bool includeHMAC = true, bool includeIV = true)
        {
            var bytes = StringEncoding.GetBytes(plaintext);
            var encrypted = EncryptBytes(bytes, includeHMAC, includeIV);
            return Convert.ToBase64String(encrypted);
        }


        public string Decrypt(string base64ciphertext, bool includeHMAC = true, bool includeIV = true)
        {
            var bytes = Convert.FromBase64String(base64ciphertext);
            var decrypted = DecryptBytes(bytes, includeHMAC, includeIV);
            return StringEncoding.GetString(decrypted);
        }


        public byte[] EncryptBytes(byte[] bytes, bool includeHMAC = true, bool includeIV = true)
        {
            if (bytes == null || bytes.Length == 0)
                return bytes;

            using (RijndaelManaged myRijndael = new RijndaelManaged())
            {
                myRijndael.Key = AesKey;

                if (includeIV)
                    myRijndael.GenerateIV();
                else
                    myRijndael.IV = new byte[myRijndael.BlockSize/8]; // initialize to 0

                byte[] IV = myRijndael.IV;


                using (HMACSHA256 hmac = (includeHMAC ? new HMACSHA256(HmacKey) : null))
                {
                    byte[] encryptedBytes;
                    byte[] hash = null;

                    if (includeHMAC)
                        hash = new byte[hmac.HashSize/8];


                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        if (includeHMAC)
                            msEncrypt.Write(hash, 0, hash.Length); // placeholder for the HMAC hash

                        if (includeIV)
                            msEncrypt.Write(IV, 0, IV.Length);

                        ICryptoTransform encryptor = myRijndael.CreateEncryptor(myRijndael.Key, IV);

                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            csEncrypt.Write(bytes, 0, bytes.Length);
                            csEncrypt.FlushFinalBlock();
                        }

                        encryptedBytes = msEncrypt.ToArray();
                    }

                    if (includeHMAC)
                    {
                        hash = hmac.ComputeHash(encryptedBytes, hash.Length, encryptedBytes.Length - hash.Length);
                        Buffer.BlockCopy(hash, 0, encryptedBytes, 0, hash.Length);
                    }

                    return encryptedBytes;
                }
            }
        }


        public byte[] DecryptBytes(byte[] bytes, bool includeHMAC = true, bool includeIV = true)
        {
            if (bytes == null || bytes.Length == 0)
                return bytes;

            int hashByteSize = 0;

            if (includeHMAC)
            {
                using (HMACSHA256 hmac = new HMACSHA256(HmacKey))
                {
                    hashByteSize = hmac.HashSize / 8;
                    byte[] computedHash = hmac.ComputeHash(bytes, hashByteSize, bytes.Length - hashByteSize);

                    VerifyHash(bytes, computedHash);
                }
            }

            using (RijndaelManaged myRijndael = new RijndaelManaged())
            {
                byte[] IV = new byte[myRijndael.BlockSize/8];

                if (includeIV)
                    Buffer.BlockCopy(bytes, hashByteSize, IV, 0, IV.Length);

                myRijndael.Key = AesKey;
                myRijndael.IV = IV;

                ICryptoTransform decryptor = myRijndael.CreateDecryptor(myRijndael.Key, myRijndael.IV);

                using (MemoryStream msDecrypt = new MemoryStream())
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                    {
                        int dataOffset = hashByteSize;

                        if (includeIV)
                            dataOffset += IV.Length;

                        csDecrypt.Write(bytes, dataOffset, bytes.Length - dataOffset);
                        csDecrypt.FlushFinalBlock();
                    }

                    return msDecrypt.ToArray();
                }
            }
        }


        [MethodImpl(MethodImplOptions.NoOptimization)]
        private void VerifyHash(byte[] actual, byte[] expected)
        {
            int hashDiff = 0;

            // Done this way so that the hash verification takes exactly the same amount of time regardless
            // of whether the hash was correct or not
            for (int i = 0; i < expected.Length; ++i)
                hashDiff |= (expected[i] ^ actual[i]);

            if (hashDiff != 0)
                throw new CryptographicException("Bad Hash.");
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Liphsoft.Crypto.Argon2
{
    public class Encryptor
    {
        public byte[] AesKey { get; set; }

        public byte[] HmacKey { get; set; }


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
                    myRijndael.IV = new byte[myRijndael.BlockSize / 8]; // initialize to 0

                byte[] IV = myRijndael.IV;


                using (HMACSHA256 hmac = (includeHMAC ? new HMACSHA256(HmacKey) : null))
                {
                    byte[] encryptedBytes;
                    byte[] hash = null;
                    
                    if(includeHMAC)
                        hash = new byte[hmac.HashSize / 8];


                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        if(includeHMAC)
                            msEncrypt.Write(hash, 0, hash.Length);  // placeholder for the HMAC hash

                        if(includeIV)
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
                    int hashDiff = 0;

                    hashByteSize = hmac.HashSize / 8;
                    byte[] computedHash = hmac.ComputeHash(bytes, hashByteSize, bytes.Length - hashByteSize);

                    // Done this way so that the hash verification takes exactly the same amount of time regardless
                    // of whether the hash was correct or not
                    for (int i = 0; i < computedHash.Length; ++i)
                        hashDiff |= (computedHash[i] ^ bytes[i]);

                    if (hashDiff != 0)
                        throw new CryptographicException("Bad Hash.");
                }
            }

            using (RijndaelManaged myRijndael = new RijndaelManaged())
            {
                byte[] IV = new byte[myRijndael.BlockSize / 8];

                if(includeIV)
                    Buffer.BlockCopy(bytes, hashByteSize, IV, 0, IV.Length);

                myRijndael.Key = AesKey;
                myRijndael.IV = IV;

                ICryptoTransform decryptor = myRijndael.CreateDecryptor(myRijndael.Key, myRijndael.IV);

                using (MemoryStream msDecrypt = new MemoryStream())
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                    {
                        int dataOffset = hashByteSize;
                        
                        if(includeIV)
                            dataOffset += IV.Length;

                        csDecrypt.Write(bytes, dataOffset, bytes.Length - dataOffset);
                        csDecrypt.FlushFinalBlock();
                    }

                    return msDecrypt.ToArray();
                }
            }
        }
    }
}

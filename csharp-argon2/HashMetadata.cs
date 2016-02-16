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

namespace Liphsoft.Crypto.Argon2
{
    /// <summary>
    /// HashMetadata represents the information stored in the encoded Argon2 format
    /// </summary>
    public class HashMetadata
    {
        /// <summary>
        /// The type of Argon2 hashing algorithm to use
        /// Argon2d - The memory access is dependent upon the hash value (vulnerable to side-channel attacks)
        /// Argon2i - The memory access is independent upon the hash value (safe from side-channel atacks)
        /// </summary>
        public Argon2Type ArgonType { get; set; }

        /// <summary>
        /// How much memory to use while hashing in kibibytes (KiB)
        /// </summary>
        public uint MemoryCost { get; set; }

        /// <summary>
        /// How many iterations of the Argon2 hash to perform
        /// </summary>
        public uint TimeCost { get; set; }

        /// <summary>
        /// How many threads to use while hashing
        /// </summary>
        public uint Parallelism { get; set; }

        /// <summary>
        /// Base-64 encoding of the salt used, minus the padding (=) characters
        /// </summary>
        public string Base64Salt { get; set; }

        /// <summary>
        /// Base-64 encoding of the resulting hash, minus the padding (=) characters
        /// </summary>
        public string Base64Hash { get; set; }


        /// <summary>
        /// The raw bytes represented by the base-64 encoded salt
        /// </summary>
        public byte[] GetSaltBytes() { return FromBase64(Base64Salt); }

        /// <summary>
        /// The raw bytes represented by the base-64 encoded hash
        /// </summary>
        public byte[] GetHashBytes() { return FromBase64(Base64Hash); }


        /// <summary>
        /// Converts HashMetadata back into the original Argon2 formatted string.
        /// </summary>
        public override string ToString()
        {
            return string.Format("$argon2{0}$m={1},t={2},p={3}${4}${5}", (ArgonType == Argon2Type.Argon2i ? "i" : "d"),
                MemoryCost, TimeCost, Parallelism, Base64Salt, Base64Hash);
        }


        private static readonly string[] Base64Padding = {"", "", "==", "="};

        private static byte[] FromBase64(string base64)
        {
            int lenMod4 = (base64.Length & 3);
            return Convert.FromBase64String(base64 + Base64Padding[lenMod4]);
        }
    }
}

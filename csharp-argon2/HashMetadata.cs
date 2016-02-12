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

namespace Liphsoft.Crypto.Argon2
{
    /// <summary>
    /// 
    /// </summary>
    public class HashMetadata
    {
        /// <summary>
        /// 
        /// </summary>
        public Argon2Type ArgonType { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public int MemoryCost { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public int TimeCost { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public int Parallelism { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public string Base64Salt { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public string Base64Hash { get; set; }


        /// <summary>
        /// 
        /// </summary>
        public byte[] GetSaltBytes() { return FromBase64(Base64Salt); }

        /// <summary>
        /// 
        /// </summary>
        public byte[] GetHashBytes() { return FromBase64(Base64Hash); }


        /// <summary>
        /// 
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

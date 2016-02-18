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
namespace Liphsoft.Crypto.Argon2
{
    /// <summary>
    /// The type of Argon2 hashing algorithm to use.
    /// </summary>
    public enum Argon2Type
    {
        /// <summary>
        /// The memory access is dependent upon the hash value (vulnerable to side-channel attacks)
        /// </summary>
        Argon2d = 0,

        /// <summary>
        /// The memory access is independent upon the hash value (safe from side-channel atacks)
        /// </summary>
        Argon2i = 1
    }
}

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
    /// An exception class to wrap the errors returned by Daniel Dinu and Dmitry Khovratovich's Argon2 library.
    /// 
    /// Except through very unusual conditions, the only exceptions which could be thrown from PasswordHasher
    /// are Argon2Exception, ArgumentNullException, DllNotFoundException (if libargon2.dll is not found)
    /// </summary>
    public class Argon2Exception : Exception
    {
        /// <summary>
        /// Construct an Argon2Exception with the specified Argon2 error code
        /// <param name="action">Which method the Argon2Exception originated from</param>
        /// <param name="error">The error returned from the Argon2 library</param>
        /// </summary>
        public Argon2Exception(string action, Argon2Error error) : base(string.Format("Error during Argon2 {0}: ({1}) {2}", action, (int)error, error)) {}
    }
}

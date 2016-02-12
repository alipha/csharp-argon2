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
namespace Liphsoft.Crypto.Argon2
{
    /// <summary>
    /// An enumeration of the possible error codes which are returned from Daniel Dinu and
    /// Dmitry Khovratovich's Argon2 library.
    /// 
    /// Some of these error conditions cannot be reached while using the C# binding
    /// </summary>
    public enum Argon2Error 
    {
        OK = 0,

        OUTPUT_PTR_NULL = 1,

        OUTPUT_TOO_SHORT = 2,
        OUTPUT_TOO_LONG = 3,

        PWD_TOO_SHORT = 4,
        PWD_TOO_LONG = 5,

        SALT_TOO_SHORT = 6,
        SALT_TOO_LONG = 7,

        AD_TOO_SHORT = 8,
        AD_TOO_LONG = 9,

        SECRET_TOO_SHORT = 10,
        SECRET_TOO_LONG = 11,

        TIME_TOO_SMALL = 12,
        TIME_TOO_LARGE = 13,

        MEMORY_TOO_LITTLE = 14,
        MEMORY_TOO_MUCH = 15,

        LANES_TOO_FEW = 16,
        LANES_TOO_MANY = 17,

        PWD_PTR_MISMATCH = 18,    /* NULL ptr with non-zero length */
        SALT_PTR_MISMATCH = 19,   /* NULL ptr with non-zero length */
        SECRET_PTR_MISMATCH = 20, /* NULL ptr with non-zero length */
        AD_PTR_MISMATCH = 21,     /* NULL ptr with non-zero length */

        MEMORY_ALLOCATION_ERROR = 22,

        FREE_MEMORY_CBK_NULL = 23,
        ALLOCATE_MEMORY_CBK_NULL = 24,

        INCORRECT_PARAMETER = 25,
        INCORRECT_TYPE = 26,

        OUT_PTR_MISMATCH = 27,

        THREADS_TOO_FEW = 28,
        THREADS_TOO_MANY = 29,

        MISSING_ARGS = 30,

        ENCODING_FAIL = 31,

        DECODING_FAIL = 32,

        THREAD_FAIL = 33,

        DECODING_LENGTH_FAIL = 34,

        ERROR_CODES_LENGTH /* Do NOT remove; Do NOT add error codes after
                                     this
                                     error code */
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Argon2
{
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

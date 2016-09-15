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
using System.Linq;

namespace Liphsoft.Crypto.Argon2
{
    class Program
    {
        private const uint T_COST_DEF = 3;
        private const int LOG_M_COST_DEF = 12;
        private const uint THREADS_DEF = 1;
        private const uint HASH_LEN_DEF = 32;
        private const int SALT_LEN = 16;

        private static void Usage()
        {
            Console.WriteLine("Usage:  Argon2 salt [-d] [-t iterations] [-m memory] [-p parallelism]");
            Console.WriteLine("\t\t[-h length] [-e|-r]");
            Console.WriteLine("\tPassword is read from stdin");
            Console.WriteLine("Parameters:");
            Console.WriteLine("\tsalt\t\tThe salt to use, at most {0} characters", SALT_LEN);
            Console.WriteLine("\t-d\t\tUse Argon2d instead of Argon2i (which is the default)");
            Console.WriteLine("\t-t N\t\tSets the number of iterations to N (default = {0})", T_COST_DEF);
            Console.WriteLine("\t-m N\t\tSets the memory usage of 2^N KiB (default {0})", LOG_M_COST_DEF);
            Console.WriteLine("\t-p N\t\tSets parallelism to N threads (default {0})", THREADS_DEF);
            Console.WriteLine("\t-h N\t\tSets hash output length to N bytes (default {0})", HASH_LEN_DEF);
            Console.WriteLine("\t-e\t\tOutput only encoded hash and metadata");
            Console.WriteLine("\t-r\t\tOutput only the raw hexadecimal of the hash");
        }

        private static void Fatal(string error)
        {
            Console.Error.WriteLine("Error: {0}", error);
            Environment.Exit(1);
        }

        private static string ToHex(byte[] bytes)
        {
            return string.Join("", bytes.Select(x => string.Format("{0:x2}", x)).ToArray());
        }

        private static uint ReadArg(string[] args, int index, string switchName, uint minValue, uint maxValue)
        {
            if(index >= args.Length)
                Fatal(string.Format("missing {0} argument", switchName));

            long value = 0;

            if(!long.TryParse(args[index], out value) || value < minValue || value > maxValue)
                Fatal(string.Format("bad numeric input for {0}. Allowed range is {1} to {2}", switchName, minValue, maxValue));

            return (uint)value;
        }

        private static void Run(PasswordHasher hasher, string pwd, string salt, bool rawOnly, bool encodedOnly)
        {
            try
            {
                if (rawOnly)
                {
                    Console.WriteLine(ToHex(hasher.HashRaw(pwd, salt)));
                    return;
                }

                if (encodedOnly)
                {
                    Console.WriteLine(hasher.Hash(pwd, salt));
                    return;
                }

                var startTime = DateTime.Now;
                string encoded = hasher.Hash(pwd, salt);
                var stopTime = DateTime.Now;
                
                HashMetadata metadata = PasswordHasher.ExtractMetadata(encoded);

                Console.WriteLine("Hash:\t\t" + ToHex(metadata.Hash));
                Console.WriteLine("Encoded:\t" + encoded);
                Console.WriteLine("{0:0.000} seconds", (stopTime - startTime).TotalSeconds);

                if(hasher.Verify(encoded, pwd))
                    Console.WriteLine("Verification ok");
                else
                    throw new Argon2Exception("verifying", Argon2Error.VERIFY_MISMATCH);
            }
            catch (Exception ex)
            {
                Fatal(ex.Message);
            }
        }

        static void Main(string[] args)
        {
            uint m_cost = (uint)(1 << LOG_M_COST_DEF);
            uint t_cost = T_COST_DEF;
            uint threads = THREADS_DEF;
            uint hash_len = HASH_LEN_DEF;
            Argon2Type type = Argon2Type.Argon2i;
            bool rawOnly = false;
            bool encodedOnly = false;

            if (args.Length == 0)
            {
                Usage();
                Environment.Exit(30);
            }
            
            var pwd = Console.In.ReadToEnd();

            if (pwd.EndsWith("\r\n"))
                pwd = pwd.Substring(0, pwd.Length - 2);
            else if(pwd.EndsWith("\n"))
                pwd = pwd.Substring(0, pwd.Length - 1);

            if (args[0].Length > SALT_LEN)
                Fatal("salt too long");

            var salt = args[0] + new string('\0', SALT_LEN - args[0].Length);

            for (var i = 1; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-m": m_cost = (1U << (int)ReadArg(args, ++i, "-m", 1, 32)); break;
                    case "-t": t_cost = ReadArg(args, ++i, "-t", 1, int.MaxValue); break;
                    case "-p": threads = ReadArg(args, ++i, "-p", 1, 0xFFFFFF); break;
                    case "-h": hash_len = ReadArg(args, ++i, "-h", 4, int.MaxValue); break;
                    case "-d": type = Argon2Type.Argon2d; break;
                    case "-e":
                    case "-encoded":
                        encodedOnly = true;
                        break;
                    case "-r":
                    case "-raw":
                        rawOnly = true;
                        break;
                    default:
                        Fatal("unknown argument " + args[i]);
                        break;
                }
            }

            if (encodedOnly && rawOnly)
                Fatal("Only one of -e or -r may be specified");

            if (!encodedOnly && !rawOnly)
            {
                Console.WriteLine("Type:\t\t{0}", type);
                Console.WriteLine("Iterations:\t{0}", t_cost);
                Console.WriteLine("Memory:\t\t{0} KiB", m_cost);
                Console.WriteLine("Parallelism:\t{0}", threads);

            }

            var hasher = new PasswordHasher(t_cost, m_cost, threads, type, hash_len);
            Run(hasher, pwd, salt, rawOnly, encodedOnly);
        }
    }
}


using System;

namespace Argon2
{
    class Program
    {
        static void Main(string[] args)
        {
            var argon2 = new PasswordHasher();
            var hash = argon2.Hash("Test");
            Console.WriteLine(hash);
            Console.WriteLine(argon2.Verify(hash, "test") + " " + argon2.Verify(hash, "Test"));
            Console.ReadLine();
        }
    }
}

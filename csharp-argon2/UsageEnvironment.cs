
namespace Liphsoft.Crypto.Argon2
{
    /// <summary>
    /// The default performance parameters to initialize the PasswordHasher with depending upon what its usage will be.
    /// You should perform your own profiling to determine what the parameters should be for your specific usage; however,
    /// this attempts to provide some reasonable defaults.
    /// </summary>
    public enum UsageEnvironment
    {
        /// <summary>
        /// The password hashing will be done server-side with potentially multiple passwords being
        /// hashed cocurrently, so use performance parameters which will cause a single hash to take under 100ms
        /// using one CPU with 2016 hardware
        /// </summary>
        Server,

        /// <summary>
        /// The password hashing will be done in a single-user application, so
        /// use performance parameters which will cause the hashing to take about 1 second using 2 CPUs with 2016 hardware
        /// </summary>
        SingleUser
    }
}

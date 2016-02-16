using System.Collections.Generic;
using Liphsoft.Crypto.Argon2;

namespace Example
{
    #region Dummy classes because I did not want to add all the MVC references

    //
    // Dummy classes to make the example compile
    //
    class Controller { }

    class ActionResult { }

    class ConfigurationManager
    {
        public static IDictionary<string, string> AppSettings
        {
            get
            {
                return new Dictionary<string, string> { { "PasswordHasher.TimeCost", "3" }, { "PasswordHasher.MemoryCost", "65536" } };
            }
        }
    }

    class User { public string PasswordHash { get; set; } }

    class LoginViewModel { public string ErrorMessage { get; set; } }

    #endregion



    class HomeController : Controller
    {
        public ActionResult Login(string username, string password)
        {
            // Do profiling to determine what the optimal time and memory cost would be for your server setup
            // Ideally, PasswordHasher.Hash should take about 200ms to perform as a good balance between security and responsiveness
            // Prefer to increase MemoryCost instead of TimeCost (increasing MemoryCost will also increase the overall time)
            // TODO: Edit your web.config or app.config to contain the following keys within your <configuration><appSettings>...</appSettings></configuration>:
            // TODO: <add key="PasswordHasher.TimeCost" value="3" />
            // TODO: <add key="PasswordHasher.MemoryCost" value="65536" />

            uint timeCost = uint.Parse(ConfigurationManager.AppSettings["PasswordHasher.TimeCost"] ?? "3");
            uint memoryCost = uint.Parse(ConfigurationManager.AppSettings["PasswordHasher.MemoryCost"] ?? "65536");
            string dummyHash = string.Format("$argon2i$m={0},t={1},p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", memoryCost, timeCost);

            var passwordHasher = new PasswordHasher(timeCost, memoryCost);
            
            // Get the user from the database in hopefully some constant-time fashion so that timing attacks
            // cannot be used to enumerate valid usernames
            User user = GetUser(username);
            string passwordHash = (user != null ? user.PasswordHash : dummyHash);
            bool updatedCost;
            string newPasswordHash;

            // always compare against a password hash even if the user is not found (when that happens, we compare against dummyHash)
            // to prevent timing attacks from enumerating a list of valid usernames
            if (passwordHasher.VerifyAndUpdate(passwordHash, password, out updatedCost, out newPasswordHash))
            {
                // VerifyAndUpdate will generate a new password hash if the time or memory cost from ConfigurationManager.AppSettings
                // does not match what was used to generate the password hash which was stored in the database.
                // This allows you to easily update the password hashing cost if you upgrade to better server hardware by
                // modifying the PasswordHasher.TimeCost and PasswordHasher.MemoryCost parameters.
                if (updatedCost)
                {
                    // As users successfully log in, update their password hash to the hash with the updated cost
                    user.PasswordHash = newPasswordHash;
                    UpdateUser(user);
                }

                // Successful login
                LogInUser(user);
                return RedirectToAction("Index", "Home");
            }

            // User failed to login
            var model = new LoginViewModel {ErrorMessage = "Username or Password is incorrect."};
            return View(model);
        }


        private User GetUser(string username)
        {
            // TODO: get the username from the database in hopefully some constant-time fashion
            return new User();
        }

        private void UpdateUser(User user)
        {
            // TODO: update the user in the database with the new password hash
        }

        private void LogInUser(User user)
        {
            // TODO: set session information, etc.
        }


        #region Dummy methods because I did not want to add all the MVC references

        // Dummy method to make the example compile
        private ActionResult RedirectToAction(string action, string controller)
        {
            return new ActionResult();
        }

        // Dummy method to make the example compile
        private ActionResult View(LoginViewModel model)
        {
            return new ActionResult();
        }

        #endregion
    }
}

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
        // This code is more complicated than necessary IF you do not care about attackers enumerating your user list via timing attacks
        public ActionResult Login(string username, string password)
        {
            // Do profiling to determine what the optimal time and memory cost would be for your server setup
            // Ideally, PasswordHasher.Hash should take about 200ms to perform as a good balance between security and responsiveness
            // Prefer to increase MemoryCost instead of TimeCost (increasing MemoryCost will also increase the overall time)
            // TODO: Edit your web.config or app.config to contain the following keys within your <configuration><appSettings>...</appSettings></configuration>:
            // TODO: <add key="PasswordHasher.TimeCost" value="3" />
            // TODO: <add key="PasswordHasher.MemoryCost" value="65536" />
            // If you are updating the time cost or memory cost (because, e.g., you moved to faster hardware) then 
            // add PasswordHasher.OldTimeCost and PasswordHasher.OldMemoryCost keys with the previous values to ensure timing attacks cannot
            // be done to enumerate the possible users. Remove OldTimeCost and OldMemoryCost when the migration is finished.

            string timeCostStr = (ConfigurationManager.AppSettings["PasswordHasher.TimeCost"] ?? "3");
            string memoryCostStr = (ConfigurationManager.AppSettings["PasswordHasher.MemoryCost"] ?? "65536");
            uint timeCost = uint.Parse(timeCostStr);
            uint memoryCost = uint.Parse(memoryCostStr);
            uint oldTimeCost = uint.Parse(ConfigurationManager.AppSettings["PasswordHasher.OldTimeCost"] ?? timeCostStr);
            uint oldMemoryCost = uint.Parse(ConfigurationManager.AppSettings["PasswordHasher.OldMemoryCost"] ?? memoryCostStr);

            bool costsDiffer = (timeCost != oldTimeCost || memoryCost != oldMemoryCost);

            string hashFormat = "$argon2i$m={0},t={1},p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            string dummyHash = string.Format(hashFormat, memoryCost, timeCost);
            string oldDummyHash = string.Format(hashFormat, oldMemoryCost, oldTimeCost);

            var passwordHasher = new PasswordHasher(timeCost, memoryCost);
            
            // Get the user from the database in hopefully some constant-time fashion so that timing attacks
            // cannot be used to enumerate valid usernames
            User user = GetUser(username);
            string passwordHash = (user != null ? user.PasswordHash : dummyHash);
            bool updatedCost;
            string newPasswordHash;

            HashMetadata hashMetadata = PasswordHasher.ExtractMetadata(passwordHash);
            bool usingOldCosts = (hashMetadata.MemoryCost != memoryCost || hashMetadata.TimeCost != timeCost);

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
                else if(costsDiffer)
                {
                    // run the verification with the old costs so that each login attempt performs a hash
                    // with the new costs and with the old costs to ensure the timing is consistent
                    passwordHasher.Verify(oldDummyHash, password);
                }

                // Successful login
                LogInUser(user);
                return RedirectToAction("Index", "Home");
            }

            // if we're migrating password hashes from the old cost parameters to new cost parameters, we want
            // each login attempt to perform a single hash with the new cost parameters and a single hash with
            // the old cost parameters so that the timing is consistent.
            if(costsDiffer)
                passwordHasher.Verify((usingOldCosts ? dummyHash : oldDummyHash), password);

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

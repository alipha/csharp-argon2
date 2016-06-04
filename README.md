# csharp-argon2
C#/.NET binding for the Argon2 password hash

## Usage

### Basic usage

To generate password hashes:

```csharp
using Liphsoft.Crypto.Argon2;

var hasher = new PasswordHasher();

string myhash = hasher.Hash("mypassword");
```

Then to verify a password matches the previously-generated hash:

```csharp
if(hasher.Verify(myhash, "mypassword"))
{
	// user entered correct password
}
```

### Customizing Hashing Parameters

It's simple to change computation power required to produce a hash. The default settings may be a little aggressive for your environment, especially if, for example, it's a webserver serving thousands of concurrent users.  The PasswordHasher constructor exposes several parameters, but the only one worth changing is generally the memory cost:

```csharp
var hasher = new PasswordHasher(memoryCost: 16384);  // default is 65536 (in KiB)
```

I would suggest storing the memory cost parameter in a configuration file so it can be easily changed in the future:

```csharp
using System.Configuration;
using Liphsoft.Crypto.Argon2;

string memoryCostStr = (ConfigurationManager.AppSettings["PasswordHasher.MemoryCost"] ?? "65536");
var hasher = new PasswordHasher(memoryCost: uint.Parse(memoryCostStr));
```

### Updating Existing Hashes with New Costs

If you decide to change the cost parameters used for the PasswordHasher, it is easy to transparently migrate hashes to the new cost parameters as users log in:

```csharp
User user = GetUserByUsername(suppliedUsername);
bool hashIsUpdated;
string newHash;

if(hasher.VerifyAndUpdate(user.PasswordHash, suppliedPassword, out hashIsUpdated, out newHash))
{
	// You could wrap this in if(hashIsUpdated) if you didn't want to waste time
	// updating the user when the hash doesn't change
	
	user.PasswordHash = newHash;  // if the hash didn't change, then newHash == user.PasswordHash
	UpdateUser(user);
	
	// continue with login process
}
else
{
	// Supplied password isn't correct
}
```

Note that users who never log in after that point will never be migrated. However, there isn't an elegant solution to that problem.
# csharp-argon2
C#/.NET binding for the Argon2 password hash

## Installation

The easiest way would be to search for [Liphsoft.Crypto.Argon2](https://www.nuget.org/packages/Liphsoft.Crypto.Argon2) in the Nuget Package Manager and install it through Nuget. You should explicitly specify in your solution using the configuration manager whether to build your solution for x86 or x64 and *not* use the default "Any CPU". You may get an error at runtime if the incorrect DLL is used because you specified your platform as "Any CPU".

### libargon2.dll web application issues

You may encounter some issues with IIS not finding the libargon2.dll or not having permissions to access the DLL. @cosmin-ionita provided a nice explanation on how to get this to work [here](https://github.com/alipha/csharp-argon2/issues/2#issuecomment-250428792).

### Building from source

To build the C# and C libraries from source, simply build the csharp-argon2 project and both Liphsoft.Crypto.Argon2.dll and libargon2.dll should be generated in the bin directory of the solution. You need both DLLs.

Note that pre-built versions of the C library, libargon2.dll, are in the `csharp-argon2\x86` and `csharp-argon2\x64` directories if you are unable to build the C project.

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

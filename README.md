# Generate a 24-word seedphrase (BIP-39)

Due to the Coldcard entropy bug, I needed to create my own version for creating a 24-word seed phrase by using proper cryptographic randomness. This console application is written in Microsoft Visual Studio 2026 with .NET Core 10 framework with help from Claude and my own changes and a couple of hours code review.
In short, the console application is using the Microsoft .NET 10 cryptography libraries to generate a 256-bit random number, plus a SHA256 checksum, which is then converted into a 24-word seed phrase according to the BIP-39 standard. The Microsoft .NET Core 10 library "System.Security.Cryptography" uses a random generator that is based on OS cryptographic libraries (Windows, Unix, macOS).

RandomNumberGenerator.Fill():
https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator.fill?view=net-10.0

SHA256.HashData():
https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha256.hashdata?view=net-10.0


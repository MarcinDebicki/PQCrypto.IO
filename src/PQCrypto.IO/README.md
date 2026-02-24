
# Deployment PQCrypto.IO library

Using the library requires preparing an environment in which you can disable swapping of selected memory pages.

**By default, the application allocates 8 MB of unmanaged memory and blocks the possibility of swapping it.**

## For Windows

### For development

Below are instructions for adding permissions to selected accounts/groups. Of course, you must have the appropriate permissions to make such changes.

![Windows lock page in memory](https://github.com/MarcinDebicki/PQCrypto.IO/windows-lock-page-in-memory.png)

### For production

During installation with administrator privileges, you can automate the process. Here's how.

Export all permissions

````
> secedit /export /cfg C:\temp\secpol.cfg
````

Open the file and find the section:

````
[Privilege Rights]
SeLockMemoryPrivilege = *S-1-5-32-544,other_accounts,other_groups
````

Save the file and import it back to the system:

````
> secedit /import /cfg C:\temp\secpol.cfg
````

### For Linux

To allow your library or application to lock memory using mlock(2), you must configure the memlock resource limit (RLIMIT_MEMLOCK). This limit defines the maximum number of bytes a process can pin in RAM to prevent them from being swapped out.

### 1. Persistent Configuration (System-wide)

For users and groups, limits are managed via the /etc/security/limits.conf file. Values are specified in kilobytes (KB).

Add these lines to the file (or a new file in /etc/security/limits.d/):

````
# Example for a specific user
username    soft    memlock  1048576
username    hard    memlock  2097152

# Or for all users (using '*')
*           soft    memlock  unlimited
*           hard    memlock  unlimited
````

*Note: A logout/login is required for these changes to take effect.*

### 2. Temporary Change (Shell Session)

Use the ulimit command to adjust limits for the current shell and its child processes:

+ Check current limit: `ulimit -l`
+ Set new limit (in KB): `ulimit -l 1048576`
+ Set to unlimited: `ulimit -l unlimited`


### 3. Systemd Services

Services managed by systemd often ignore limits.conf. You must set the limit directly in the service unit file:

````
[Service]
LimitMEMLOCK=infinity
````

Apply the changes by running systemctl daemon-reload and restarting the service.

### 4. Running Processes

To modify limits for an already running process without restarting it, use the prlimit utility:

````
# Example: Set soft and hard limits for PID 1234
> prlimit --pid 1234 --memlock=1048576:2097152
````

### 5. Docker Containers

If your library runs inside a container, you must pass the limit during the docker run command: 

````
> docker run --ulimit memlock=-1:-1 <image_name>
````

# Acknowledgments

This package wouldn't have been possible without the work surrounding the project https://github.com/open-quantum-safe/liboqs. Truly amazing work, and a huge thanks for your dedication.

# My Motivation

This package was created as part of a cryptosystem I am working on. It was therefore developed to meet a current project need.  
My goal was not to create wrappers for all available algorithms but to focus on specific ones that I hope to use.  
If it proves useful to someone else, I’ll be happy.

# Native Libraries

The package includes native libraries for Windows and Linux systems.  
Thanks to the consistent API of liboqs, a balance was found between usage universality, genericity, and cross-platform compatibility.

I understand that, while reviewing the code, you may think it looks almost identical for each algorithm.  
In fact, until I encountered issues generating key pairs for ClassicMcEliece8192128 and ClassicMcEliece6688128, I was aiming for fully generic code.  
**The code is the way it is because that’s exactly how it’s supposed to be**, allowing me to quickly address any issues if they arise without introducing major changes. I believe no one who wants to use it would appreciate revolutionary changes.

The project includes natively compiled versions of liboqs for Windows and Linux. Detailed information on compiling liboqs can be found on the liboqs project pages.  
I am not including instructions for building native libraries (because even I don't really like these scripts), but I will have no problem if you replace them with your own.

# This is a C# Project

Cryptography involves constant operations on byte arrays, an approach far from object-oriented programming.  
To prevent silly mistakes, all byte arrays are encapsulated in strongly typed objects.  
For implementation flexibility, every library component is also an interface.

I encourage you not to use types in your programs that could be interpreted differently by various parts of the program.

# Changes February 2026
I am giving up on trying to keep up with subsequent releases of liboqs. The library can now support many different cryptographic libraries and multiple versions of those libraries without compromising mental health. However, I have no plans to include other cryptographic libraries at this time.

All keys that should be protected are stored in unmanaged memory, which cannot be moved or used by the operating system for swap files. Before starting development work, please review the Windows/Linux permissions for blocking pages at the beginning of this document. In the case of hibernation, I leave the decision of what to do to the architects and developers. However, you can easily clear all buffers by running the Clean method in the manager:

```
ProtectMemoryManager.ClearAllBuffers();
```

Programmatically allocating and freeing memory resources in unmanaged memory was somewhat challenging for me. When protected memory starts running out of space to allocate new memory, I move blocks around to reduce fragmentation and create a larger, contiguous block of memory. This task requires not only computing power, but also exclusive locking of such a resource.

You won't have many opportunities to encounter such data, but if you really want to use data from protected memory, you must first lock the object for exclusive use yourself. The only safe way to transfer data to managed memory is to use `Span<byte> buffer = stackalloc byte[length]` and copy the data from unmanaged memory to managed memory. I fully understand that `Span<byte>` is not convenient.

__Important note: Simple conversion from `Span<byte>` using `ToArray()` is a potential source of secret leaks.__

Below is the correct use of locking, copying, and clearing memory.

```
MemorySafe memorySafe = ...; // some MemorySafe object
Span<byte> secureBuffer = stackalloc byte[memorySafe.Length];

using(memorySafe.Acquire()) {
  // e.g. view your data:
  var bytes = memorySafe.AsSpan();
  // copy to your buffer
  bytes.CopyTo(secureBuffer);
}

// use your data in secureBuffer
...
// clear the buffer after use
secureBuffer.Clear();

```

The object also includes primitive methods for locking and unlocking the object, but the approach shown seems to be the safest way. Don't worry if you forget to lock the memory—the library will throw an exception.

__If you are already using this library somewhere, I apologize for changing the API.__

# An Example of Use is Found in the Project PQCrypto.IO.POC

```
internal class Program
{
    private static void DigitalSignature()
    {
        //Arrange
        using var generator = RandomNumberGenerator.Create();
        var msg = new byte[100];
        generator.GetBytes(msg);

        IDigitalSignatureProviderFactory pqcFactory = new DigitalSignatureProviderFactory();
        var crystalsDilithium2Provider = pqcFactory.Create(DigitalSignatureAlgorithm.CrystalsDilithium2);
        var keyPair = crystalsDilithium2Provider.GenerateKeyPair();

        var privateKey = keyPair.PrivateKey;
        var publicKey = keyPair.PublicKey;
        var message = new Message(msg);

        //Act
        var signature = crystalsDilithium2Provider.Sign(message, privateKey);
        var verify = crystalsDilithium2Provider.Verify(message, signature, publicKey);

        //Post mortem

        //Safe to use stackalloc here since the buffer is only used within this method and does not escape its scope
        Span<byte> privateKeyBuffer = stackalloc byte[privateKey.Value.Length];

        // Access to Pointer && AsSpan() requires locking the MemorySafe object
        using (privateKey.Value.Acquire())
        {
            privateKey.Value.AsSpan().CopyTo(privateKeyBuffer);
        }

        Console.WriteLine("--CrystalsDilithium2-------------------");
        // Using Span.ToArray() is not very correct, but it is sufficient for demonstration purposes.
        Console.WriteLine($"Private Key: {BitConverter.ToString(privateKeyBuffer.ToArray()).ToUpper()}");
        Console.WriteLine($"Public Key: {BitConverter.ToString(publicKey.Value).ToUpper()}");
        Console.WriteLine($"Message: {BitConverter.ToString(message.Value).ToUpper()}");
        Console.WriteLine($"Signature: {BitConverter.ToString(signature.Value).ToUpper()}");
        Console.WriteLine($"Signature correctness: {verify}");

        // Clear the private key buffer from memory
        privateKeyBuffer.Clear();
    }

    private static void KeyEncapsulationMechanism()
    {
        //Arrange
        IKeyEncapsulationProviderFactory pqcFactory = new KeyEncapsulationProviderFactory();
        var crystalsKyber512Provider = pqcFactory.Create(KeyEncapsulationAlgorithm.CrystalsKyber512);
        var keyPair = crystalsKyber512Provider.GenerateKeyPair();

        var publicKey = keyPair.PublicKey;
        var privateKey = keyPair.PrivateKey;

        //Act
        var keyEncapsulationResult = crystalsKyber512Provider.Encapsulation(publicKey);
        var ciphertext = keyEncapsulationResult.KeyEncapsulationCiphertext;
        var keyDecapsulationResult = crystalsKyber512Provider.Decapsulation(ciphertext, privateKey);

        //Post mortem
        //Safe to use stackalloc here since the buffer is only used within this method and does not escape its scope
        Span<byte> keyDecapsulationBuffer = stackalloc byte[keyDecapsulationResult.KeyEncapsulationSharedSecret.Value.Length];
        Span<byte> keyEncapsulationBuffer = stackalloc byte[keyEncapsulationResult.KeyEncapsulationSharedSecret.Value.Length];

        // Access to Pointer && AsSpan() requires locking the MemorySafe object
        using (keyDecapsulationResult.KeyEncapsulationSharedSecret.Value.Acquire())
        using (keyEncapsulationResult.KeyEncapsulationSharedSecret.Value.Acquire())
        {
            keyDecapsulationResult.KeyEncapsulationSharedSecret.Value.AsSpan().CopyTo(keyDecapsulationBuffer);
            keyEncapsulationResult.KeyEncapsulationSharedSecret.Value.AsSpan().CopyTo(keyEncapsulationBuffer);
        }

        var verify = keyDecapsulationBuffer.SequenceEqual(keyEncapsulationBuffer);

        // Access to Pointer && AsSpan() requires locking the MemorySafe object
        using var @use1 = privateKey.Value.Acquire();
        using var @use2 = keyEncapsulationResult.KeyEncapsulationSharedSecret.Value.Acquire();

        Console.WriteLine("--CrystalsKyber512-------------------");
        Console.WriteLine($"Private Key: {BitConverter.ToString(privateKey.Value.AsSpan().ToArray()).ToUpper()}");
        Console.WriteLine($"Public Key: {BitConverter.ToString(publicKey.Value).ToUpper()}");
        Console.WriteLine($"Shared Secret: {BitConverter.ToString(keyEncapsulationResult.KeyEncapsulationSharedSecret.Value.AsSpan().ToArray()).ToUpper()}");
        Console.WriteLine($"Ciphertext: {BitConverter.ToString(ciphertext.Value).ToUpper()}");
        Console.WriteLine($"Decryption correctness: {verify}");

        // Clear the private key buffer from memory
        keyDecapsulationBuffer.Clear();
        keyEncapsulationBuffer.Clear();
    }

    private static void Main(string[] args)
    {
        DigitalSignature();
        KeyEncapsulationMechanism();
    }
}

```
# If you have any questions or don't understand something

Please email me at: mentatd@gmail.com

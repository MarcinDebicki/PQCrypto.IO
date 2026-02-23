
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

All keys that should be protected are stored in memory that is not subject to swapping by the operating system. Before development, please read about Windows permissions for SeLockMemoryPrivilege. In the case of hibernation, I leave the decision on what to do to the architects and programmers. However, you can easily clear all buffers by running the Clean method on the manager:

```
ProtectMemoryManager.ClearAllBuffers();
```

Programmatic allocation and release of memory resources in unmanaged memory was somewhat challenging for me. When the protected memory buffer starts to run out of space, I move blocks to reduce fragmentation and create a larger contiguous memory block. This task requires not only strength, but also exclusive locking of such a resource.
You won't have many opportunities to look at such data, but if you really want to use data from protected memory, you will first have to lock the object for exclusive use yourself, e.g. using:

```
MemorySafe memorySafe = ...; // some MemorySafe object

using(memorySafe.Acquire()) {
  // e.g. view your data:
  var bytes = memorySafe.AsSpan();
}

```

The object also includes primitive methods for locking and unlocking the object, but the approach shown seems to be the safest way. Don't worry if you forget to lock the memory—the library will throw an exception.

__If you are already using this library somewhere, I apologize for changing the API.__

# An Example of Use is Found in the Project PQCrypto.IO.POC

```
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
        // Access to Pointer && AsSpan() requires locking the MemorySafe object
        using var use1 = privateKey.Value.Acquire();

        Console.WriteLine("--CrystalsDilithium2-------------------");
        Console.WriteLine($"Private Key: {BitConverter.ToString(privateKey.Value.AsSpan().ToArray()).ToUpper()}");
        Console.WriteLine($"Public Key: {BitConverter.ToString(publicKey.Value).ToUpper()}");
        Console.WriteLine($"Message: {BitConverter.ToString(message.Value).ToUpper()}");
        Console.WriteLine($"Signature: {BitConverter.ToString(signature.Value).ToUpper()}");
        Console.WriteLine($"Signature correctness: {verify}");
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
        byte[] array1;
        byte[] array2;

        // Access to Pointer && AsSpan() requires locking the MemorySafe object
        using (keyDecapsulationResult.KeyEncapsulationSharedSecret.Value.Acquire())
        using (keyEncapsulationResult.KeyEncapsulationSharedSecret.Value.Acquire())
        {
            array1 = keyDecapsulationResult.KeyEncapsulationSharedSecret.Value.AsSpan().ToArray();
            array2 = keyEncapsulationResult.KeyEncapsulationSharedSecret.Value.AsSpan().ToArray();
        }

        var verify = array1.SequenceEqual(array2);

        // Access to Pointer && AsSpan() requires locking the MemorySafe object
        using var @use1 = privateKey.Value.Acquire();
        using var @use2 = keyEncapsulationResult.KeyEncapsulationSharedSecret.Value.Acquire();

        Console.WriteLine("--CrystalsKyber512-------------------");
        Console.WriteLine($"Private Key: {BitConverter.ToString(privateKey.Value.AsSpan().ToArray()).ToUpper()}");
        Console.WriteLine($"Public Key: {BitConverter.ToString(publicKey.Value).ToUpper()}");
        Console.WriteLine($"Shared Secret: {BitConverter.ToString(keyEncapsulationResult.KeyEncapsulationSharedSecret.Value.AsSpan().ToArray()).ToUpper()}");
        Console.WriteLine($"Ciphertext: {BitConverter.ToString(ciphertext.Value).ToUpper()}");
        Console.WriteLine($"Decryption correctness: {verify}");
    }

    private static void Main(string[] args)
    {
        DigitalSignature();
        KeyEncapsulationMechanism();
    }

```
# If you have any questions or don't understand something

Please email me at: mentatd@gmail.com

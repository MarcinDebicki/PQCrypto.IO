namespace PQCrypto.IO.POC;

using System.Security.Cryptography;
using PQCrypto.IO.Internal;

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

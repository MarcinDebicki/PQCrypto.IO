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
        Console.WriteLine("--CrystalsDilithium2-------------------");
        Console.WriteLine($"Private Key: {BitConverter.ToString(privateKey.Value).ToUpper()}");
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
        var verify = keyDecapsulationResult.KeyEncapsulationSharedSecret.Value.SequenceEqual(keyEncapsulationResult.KeyEncapsulationSharedSecret.Value);

        //Post mortem
        Console.WriteLine("--CrystalsKyber512-------------------");
        Console.WriteLine($"Private Key: {BitConverter.ToString(privateKey.Value).ToUpper()}");
        Console.WriteLine($"Public Key: {BitConverter.ToString(publicKey.Value).ToUpper()}");
        Console.WriteLine($"Shared Secret: {BitConverter.ToString(keyEncapsulationResult.KeyEncapsulationSharedSecret.Value).ToUpper()}");
        Console.WriteLine($"Ciphertext: {BitConverter.ToString(ciphertext.Value).ToUpper()}");
        Console.WriteLine($"Decryption correctness: {verify}");
    }

    private static void Main(string[] args)
    {
        DigitalSignature();
        KeyEncapsulationMechanism();
    }
}

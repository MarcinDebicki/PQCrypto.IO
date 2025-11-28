
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
For my (and your) convenience, I’ve included a `liboqs` directory containing my recipe for building the libraries from source. However, you must have all the necessary compilation and linking tools properly installed on your machine for both Windows and Linux via WSL.

# This is a C# Project

Cryptography involves constant operations on byte arrays, an approach far from object-oriented programming.  
To prevent silly mistakes, all byte arrays are encapsulated in strongly typed objects.  
For implementation flexibility, every library component is also an interface.

I encourage you not to use types in your programs that could be interpreted differently by various parts of the program.

# An Example of Use is Found in the Project pqcrypto.liboqs.ExampleOfUse

The *//Post mortem* block serves as “proof of functionality” unless the *verify* variable returns `false`.  
It couldn’t be any simpler without losing the abstraction layer.


    internal class Message : IMessage
    {
        public byte[] Value { get; }
    
        public Message(byte[] value)
        {
            this.Value = value;
        }
    }
    
    internal class Program
    {
        private static void KeyEncapsulationMechanism()
        {
            //Arrange
            IAsymmetricKemProviderFactory pqcFactory = new AsymmetricKemProviderFactory();
            var crystalsKyber512Provider = pqcFactory.Create(AlgorithmVariant.CrystalsKyber512);
            var keyPair = crystalsKyber512Provider.GenerateKeyPair();
    
            var publicKey = keyPair.PublicKey;
            var privateKey = keyPair.PrivateKey;
    
            //Act
            var sessionKey = crystalsKyber512Provider.GenerateSessionKey(publicKey);
            var secretSessionKey = sessionKey.SecretSessionKey;
            var decryptedSessionKey = crystalsKyber512Provider.DecryptSessionKey(secretSessionKey, privateKey);
            var verify = decryptedSessionKey.PlainSessionKey.Value.SequenceEqual(sessionKey.PlainSessionKey.Value);
    
            //Post mortem
            Console.WriteLine("--CrystalsKyber512-------------------");
            Console.WriteLine($"Private Key: {BitConverter.ToString(privateKey.Value).ToUpper()}");
            Console.WriteLine($"Public Key: {BitConverter.ToString(publicKey.Value).ToUpper()}");
            Console.WriteLine($"Plain sessionKey: {BitConverter.ToString(sessionKey.PlainSessionKey.Value).ToUpper()}");
            Console.WriteLine($"Secret sessionKey: {BitConverter.ToString(secretSessionKey.Value).ToUpper()}");
            Console.WriteLine($"Validation encryption: {verify}");
        }
    
        private static void Main(string[] args)
        {
            Signing();
            KeyEncapsulationMechanism();
        }
    
        private static void Signing()
        {
            //Arrange
            using var generator = RandomNumberGenerator.Create();
            var msg = new byte[100];
            generator.GetBytes(msg);
    
            IAsymmetricSignProviderFactory pqcFactory = new AsymmetricSignProviderFactory();
            var crystalsDilithium2Provider = pqcFactory.Create(AlgorithmVariant.CrystalsDilithium2);
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
            Console.WriteLine($"Validation signature: {verify}");
        }
    }

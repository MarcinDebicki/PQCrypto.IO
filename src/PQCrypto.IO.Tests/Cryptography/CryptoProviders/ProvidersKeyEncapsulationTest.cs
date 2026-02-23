namespace PQCrypto.IO.Tests.Cryptography.CryptoProviders;

using System.Security.Cryptography;
using NUnit.Framework;
using PQCrypto.IO.Internal;
using Is = NUnit.DeepObjectCompare.Is;

[TestFixture]
public sealed class ProvidersKeyEncapsulationTest
{
    public static IEnumerable<KeyEncapsulationParameters> GenerateTestCasesParameters()
    {
        yield return new KeyEncapsulationParameters
        {
            KeyEncapsulationAlgorithm = KeyEncapsulationAlgorithm.ClassicMcEliece348864,
            LengthCiphertext = 96,
            LengthPublicKey = 261120,
            LengthSecretKey = 6492,
            LengthSharedSecret = 32,
        };

        yield return new KeyEncapsulationParameters
        {
            KeyEncapsulationAlgorithm = KeyEncapsulationAlgorithm.ClassicMcEliece460896,
            LengthCiphertext = 156,
            LengthPublicKey = 524160,
            LengthSecretKey = 13608,
            LengthSharedSecret = 32,
        };

        yield return new KeyEncapsulationParameters
        {
            KeyEncapsulationAlgorithm = KeyEncapsulationAlgorithm.ClassicMcEliece6688128,
            LengthCiphertext = 208,
            LengthPublicKey = 1044992,
            LengthSecretKey = 13932,
            LengthSharedSecret = 32,
        };

        yield return new KeyEncapsulationParameters
        {
            KeyEncapsulationAlgorithm = KeyEncapsulationAlgorithm.ClassicMcEliece6960119,
            LengthCiphertext = 194,
            LengthPublicKey = 1047319,
            LengthSecretKey = 13948,
            LengthSharedSecret = 32,
        };

        yield return new KeyEncapsulationParameters
        {
            KeyEncapsulationAlgorithm = KeyEncapsulationAlgorithm.ClassicMcEliece8192128,
            LengthCiphertext = 208,
            LengthPublicKey = 1357824,
            LengthSecretKey = 14120,
            LengthSharedSecret = 32,
        };

        yield return new KeyEncapsulationParameters
        {
            KeyEncapsulationAlgorithm = KeyEncapsulationAlgorithm.CrystalsKyber512,
            LengthCiphertext = 768,
            LengthPublicKey = 800,
            LengthSecretKey = 1632,
            LengthSharedSecret = 32,
        };

        yield return new KeyEncapsulationParameters
        {
            KeyEncapsulationAlgorithm = KeyEncapsulationAlgorithm.CrystalsKyber768,
            LengthCiphertext = 1088,
            LengthPublicKey = 1184,
            LengthSecretKey = 2400,
            LengthSharedSecret = 32,
        };

        yield return new KeyEncapsulationParameters
        {
            KeyEncapsulationAlgorithm = KeyEncapsulationAlgorithm.CrystalsKyber1024,
            LengthCiphertext = 1568,
            LengthPublicKey = 1568,
            LengthSecretKey = 3168,
            LengthSharedSecret = 32,
        };

        yield return new KeyEncapsulationParameters
        {
            KeyEncapsulationAlgorithm = KeyEncapsulationAlgorithm.Hqc128,
            LengthCiphertext = 4433,
            LengthPublicKey = 2249,
            LengthSecretKey = 2305,
            LengthSharedSecret = 64,
        };

        yield return new KeyEncapsulationParameters
        {
            KeyEncapsulationAlgorithm = KeyEncapsulationAlgorithm.Hqc192,
            LengthCiphertext = 8978,
            LengthPublicKey = 4522,
            LengthSecretKey = 4586,
            LengthSharedSecret = 64,
        };

        yield return new KeyEncapsulationParameters
        {
            KeyEncapsulationAlgorithm = KeyEncapsulationAlgorithm.Hqc256,
            LengthCiphertext = 14421,
            LengthPublicKey = 7245,
            LengthSecretKey = 7317,
            LengthSharedSecret = 64,
        };
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void GenerateKeyPair_Should_Return_Valid_KeyPair(KeyEncapsulationParameters keyEncapsulationParameters)
    {
        // Arrange
        var factory = new KeyEncapsulationProviderFactory();
        var provider = factory.Create(keyEncapsulationParameters.KeyEncapsulationAlgorithm);

        // Act
        var keyPair = provider.GenerateKeyPair();

        // Assert
        Assert.That(keyPair, Is.Not.Null);
        Assert.That(keyPair.PublicKey.Value, Is.Not.Null.And.Not.Empty);
        Assert.That(keyPair.PrivateKey.Value, Is.Not.Null);

        Assert.That(keyPair.PublicKey.Value.Length, Is.EqualTo(keyEncapsulationParameters.LengthPublicKey));
        Assert.That(keyPair.PrivateKey.Value.Length, Is.EqualTo(keyEncapsulationParameters.LengthSecretKey));
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void Encapsulation_Should_Return_Valid_Ciphertext_And_SharedSecret(KeyEncapsulationParameters keyEncapsulationParameters)
    {
        // Arrange
        var factory = new KeyEncapsulationProviderFactory();
        var provider = factory.Create(keyEncapsulationParameters.KeyEncapsulationAlgorithm);
        var keyPair = provider.GenerateKeyPair();

        // Act
        var result = provider.Encapsulation(keyPair.PublicKey);

        // Assert
        Assert.That(result.KeyEncapsulationCiphertext.Value, Is.Not.Null.And.Not.Empty);
        Assert.That(result.KeyEncapsulationSharedSecret.Value, Is.Not.Null);

        Assert.That(result.KeyEncapsulationCiphertext.Value.Length, Is.EqualTo(keyEncapsulationParameters.LengthCiphertext));
        Assert.That(result.KeyEncapsulationSharedSecret.Value.Length, Is.EqualTo(keyEncapsulationParameters.LengthSharedSecret));
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void Decapsulation_Should_Return_Same_SharedSecret_As_Encapsulation(KeyEncapsulationParameters keyEncapsulationParameters)
    {
        // Arrange
        var factory = new KeyEncapsulationProviderFactory();
        var provider = factory.Create(keyEncapsulationParameters.KeyEncapsulationAlgorithm);
        var keyPair = provider.GenerateKeyPair();
        var encapsulationResult = provider.Encapsulation(keyPair.PublicKey);

        // Act
        var decapsulationResult = provider.Decapsulation(encapsulationResult.KeyEncapsulationCiphertext, keyPair.PrivateKey);

        // Assert
        Assert.That(decapsulationResult.LibVersion, Is.EqualTo(encapsulationResult.LibVersion));
        Assert.That(decapsulationResult.KeyEncapsulationAlgorithm, Is.EqualTo(encapsulationResult.KeyEncapsulationAlgorithm));

        Assert.That(decapsulationResult.KeyEncapsulationCiphertext.LibVersion, Is.EqualTo(encapsulationResult.KeyEncapsulationCiphertext.LibVersion));
        Assert.That(decapsulationResult.KeyEncapsulationCiphertext.KeyEncapsulationAlgorithm, Is.EqualTo(encapsulationResult.KeyEncapsulationCiphertext.KeyEncapsulationAlgorithm));
        Assert.That(decapsulationResult.KeyEncapsulationCiphertext.Value, Is.DeepEqualTo(encapsulationResult.KeyEncapsulationCiphertext.Value));

        Assert.That(decapsulationResult.KeyEncapsulationSharedSecret.LibVersion, Is.EqualTo(encapsulationResult.KeyEncapsulationSharedSecret.LibVersion));
        Assert.That(decapsulationResult.KeyEncapsulationSharedSecret.KeyEncapsulationAlgorithm, Is.EqualTo(encapsulationResult.KeyEncapsulationSharedSecret.KeyEncapsulationAlgorithm));
        using var use1 = decapsulationResult.KeyEncapsulationSharedSecret.Value.Acquire();
        using var use2 = encapsulationResult.KeyEncapsulationSharedSecret.Value.Acquire();

        var array1 = decapsulationResult.KeyEncapsulationSharedSecret.Value.AsSpan().ToArray();
        var array2 = encapsulationResult.KeyEncapsulationSharedSecret.Value.AsSpan().ToArray();

        var res = array1.SequenceEqual(array2);

        if (res is false)
        {
        }

        Assert.That(array1, Is.DeepEqualTo(array2));
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void Encapsulation_With_Null_PublicKey_Should_Throw_ArgumentNullException(
        KeyEncapsulationParameters keyEncapsulationParameters)
    {
        // Arrange
        var factory = new KeyEncapsulationProviderFactory();
        var provider = factory.Create(keyEncapsulationParameters.KeyEncapsulationAlgorithm);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => provider.Encapsulation(null));
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void Encapsulation_With_Empty_PublicKey_Should_Throw_WrongByteArrayLengthException(KeyEncapsulationParameters keyEncapsulationParameters)
    {
        // Arrange
        var factory = new KeyEncapsulationProviderFactory();
        var provider = factory.Create(keyEncapsulationParameters.KeyEncapsulationAlgorithm);

        var emptyPublicKey = new KeyEncapsulationPublicKey(keyEncapsulationParameters.KeyEncapsulationAlgorithm, LibVersion.libopq_0_15_0_1, Array.Empty<byte>());

        // Act & Assert
        Assert.Throws<WrongByteArrayLengthException>(() => provider.Encapsulation(emptyPublicKey));
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void Encapsulation_With_Invalid_PublicKey_Length_Should_Throw_WrongByteArrayLengthException(KeyEncapsulationParameters keyEncapsulationParameters)
    {
        // Arrange
        var factory = new KeyEncapsulationProviderFactory();
        var provider = factory.Create(keyEncapsulationParameters.KeyEncapsulationAlgorithm);
        var value = new byte[10];
        var invalidPublicKey = new KeyEncapsulationPublicKey(keyEncapsulationParameters.KeyEncapsulationAlgorithm, LibVersion.libopq_0_15_0_1, value);

        // Act & Assert
        Assert.Throws<WrongByteArrayLengthException>(() => provider.Encapsulation(invalidPublicKey));
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void Decapsulation_With_Null_Ciphertext_Should_Throw_ArgumentNullException(KeyEncapsulationParameters keyEncapsulationParameters)
    {
        // Arrange
        var factory = new KeyEncapsulationProviderFactory();
        var provider = factory.Create(keyEncapsulationParameters.KeyEncapsulationAlgorithm);
        var keyPair = provider.GenerateKeyPair();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => provider.Decapsulation(keyEncapsulationCiphertext: null, keyPair.PrivateKey));
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void Decapsulation_With_Null_PrivateKey_Should_Throw_ArgumentNullException(KeyEncapsulationParameters keyEncapsulationParameters)
    {
        // Arrange
        var factory = new KeyEncapsulationProviderFactory();
        var provider = factory.Create(keyEncapsulationParameters.KeyEncapsulationAlgorithm);
        var keyPair = provider.GenerateKeyPair();
        var encapsulationResult = provider.Encapsulation(keyPair.PublicKey);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => provider.Decapsulation(encapsulationResult.KeyEncapsulationCiphertext, keyEncapsulationPrivateKey: null));
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void Decapsulation_With_Empty_Ciphertext_Should_Throw_WrongByteArrayLengthException(KeyEncapsulationParameters keyEncapsulationParameters)
    {
        // Arrange
        var factory = new KeyEncapsulationProviderFactory();
        var provider = factory.Create(keyEncapsulationParameters.KeyEncapsulationAlgorithm);
        var keyPair = provider.GenerateKeyPair();
        var emptyCiphertext = new KeyEncapsulationCiphertext(keyEncapsulationParameters.KeyEncapsulationAlgorithm, LibVersion.libopq_0_15_0_1, Array.Empty<byte>());

        // Act & Assert
        Assert.Throws<WrongByteArrayLengthException>(() => provider.Decapsulation(emptyCiphertext, keyPair.PrivateKey));
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void Decapsulation_With_Empty_PrivateKey_Should_Throw_WrongByteArrayLengthException(KeyEncapsulationParameters keyEncapsulationParameters)
    {
        // Arrange
        var factory = new KeyEncapsulationProviderFactory();
        var provider = factory.Create(keyEncapsulationParameters.KeyEncapsulationAlgorithm);
        var keyPair = provider.GenerateKeyPair();
        var encapsulationResult = provider.Encapsulation(keyPair.PublicKey);
        var emptyPrivateKey = new KeyEncapsulationPrivateKey(keyEncapsulationParameters.KeyEncapsulationAlgorithm, LibVersion.libopq_0_15_0_1, new MemorySafe(IntPtr.Zero, length: 0, owner: null));

        // Act & Assert
        Assert.Throws<WrongByteArrayLengthException>(() => provider.Decapsulation(encapsulationResult.KeyEncapsulationCiphertext, emptyPrivateKey));
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void Decapsulation_With_Invalid_Ciphertext_Length_Should_Throw_WrongByteArrayLengthException(KeyEncapsulationParameters keyEncapsulationParameters)
    {
        // Arrange
        var factory = new KeyEncapsulationProviderFactory();
        var provider = factory.Create(keyEncapsulationParameters.KeyEncapsulationAlgorithm);
        var keyPair = provider.GenerateKeyPair();
        var invalidCiphertext = new KeyEncapsulationCiphertext(keyEncapsulationParameters.KeyEncapsulationAlgorithm, LibVersion.libopq_0_15_0_1, new byte[10]);

        // Act & Assert
        Assert.Throws<WrongByteArrayLengthException>(() => provider.Decapsulation(invalidCiphertext, keyPair.PrivateKey));
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void Decapsulation_With_Invalid_PrivateKey_Length_Should_Throw_WrongByteArrayLengthException(KeyEncapsulationParameters keyEncapsulationParameters)
    {
        // Arrange
        var factory = new KeyEncapsulationProviderFactory();
        var provider = factory.Create(keyEncapsulationParameters.KeyEncapsulationAlgorithm);
        var keyPair = provider.GenerateKeyPair();
        var encapsulationResult = provider.Encapsulation(keyPair.PublicKey);
        var invalidPrivateKey = new KeyEncapsulationPrivateKey(keyEncapsulationParameters.KeyEncapsulationAlgorithm, LibVersion.libopq_0_15_0_1, new MemorySafe(IntPtr.Zero, length: 10, owner: null)); // Nieprawidłowa długość

        // Act & Assert
        Assert.Throws<WrongByteArrayLengthException>(() => provider.Decapsulation(encapsulationResult.KeyEncapsulationCiphertext, invalidPrivateKey));
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void Decapsulation_With_Corrupted_Ciphertext_Should_Return_Different_SharedSecret(KeyEncapsulationParameters keyEncapsulationParameters)
    {
        // Arrange
        var factory = new KeyEncapsulationProviderFactory();
        var provider = factory.Create(keyEncapsulationParameters.KeyEncapsulationAlgorithm);
        var keyPair = provider.GenerateKeyPair();
        var encapsulationResult = provider.Encapsulation(keyPair.PublicKey);

        // We modify the ciphertext (change one byte)
        var corruptedCiphertextBytes = encapsulationResult.KeyEncapsulationCiphertext.Value.ToArray();
        corruptedCiphertextBytes[0] ^= 0xFF;

        var corruptedCiphertext = new KeyEncapsulationCiphertext(keyEncapsulationParameters.KeyEncapsulationAlgorithm, LibVersion.libopq_0_15_0_1, corruptedCiphertextBytes);

        // Act & Assert
        // Some algorithms (e.g., HQC) throw an exception, others return a different shared secret.
        try
        {
            var decapsulationResult = provider.Decapsulation(corruptedCiphertext, keyPair.PrivateKey);

            // If no exception was thrown, SharedSecret should be different.
            Assert.That(decapsulationResult.KeyEncapsulationSharedSecret.Value, Is.Not.EqualTo(encapsulationResult.KeyEncapsulationSharedSecret.Value),
                "Corrupted ciphertext should produce different shared secret");
        }
        catch (CryptographicException)
        {
            // Expected behavior for some algorithms (e.g., Hqc)
            Assert.Pass("Algorithm correctly detected corrupted ciphertext and threw exception");
        }
    }

    [Test]
    public void Factory_Create_With_Invalid_Algorithm_Should_Throw_ArgumentException()
    {
        // Arrange
        var factory = new KeyEncapsulationProviderFactory();
        var invalidAlgorithm = (KeyEncapsulationAlgorithm)999;

        // Act & Assert
        Assert.Throws<NotSupportedException>(() => factory.Create(invalidAlgorithm));
    }

    [Test]
    public void Factory_Create_With_Default_Algorithm_Value_Should_Throw_ArgumentException()
    {
        // Arrange
        var factory = new KeyEncapsulationProviderFactory();
        var defaultAlgorithm = default(KeyEncapsulationAlgorithm);

        // Act & Assert
        Assert.Throws<NotSupportedException>(() => factory.Create(defaultAlgorithm));
    }
}

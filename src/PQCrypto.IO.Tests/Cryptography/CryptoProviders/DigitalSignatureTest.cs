namespace PQCrypto.IO.Tests.Cryptography.CryptoProviders;

using System.Security.Cryptography;
using NUnit.Framework;
using PQCrypto.IO.Internal;

[TestFixture]
public class DigitalSignatureTest
{
    public static IEnumerable<DigitalSignatureParameters> GenerateTestCasesParameters()
    {
        yield return new DigitalSignatureParameters
        {
            DigitalSignatureAlgorithm = DigitalSignatureAlgorithm.CrystalsDilithium2,
            LengthSecretKey = 2560,
            LengthPublicKey = 1312,
            LengthSignature = 2420,
            ShorterSignature = false,
        };

        yield return new DigitalSignatureParameters
        {
            DigitalSignatureAlgorithm = DigitalSignatureAlgorithm.CrystalsDilithium3,
            LengthSecretKey = 4032,
            LengthPublicKey = 1952,
            LengthSignature = 3309,
            ShorterSignature = false,
        };

        yield return new DigitalSignatureParameters
        {
            DigitalSignatureAlgorithm = DigitalSignatureAlgorithm.CrystalsDilithium5,
            LengthSecretKey = 4896,
            LengthPublicKey = 2592,
            LengthSignature = 4627,
            ShorterSignature = false,
        };

        yield return new DigitalSignatureParameters
        {
            DigitalSignatureAlgorithm = DigitalSignatureAlgorithm.Falcon512,
            LengthSecretKey = 1281,
            LengthPublicKey = 897,
            LengthSignature = 752,
            ShorterSignature = true,
        };

        yield return new DigitalSignatureParameters
        {
            DigitalSignatureAlgorithm = DigitalSignatureAlgorithm.Falcon1024,
            LengthSecretKey = 2305,
            LengthPublicKey = 1793,
            LengthSignature = 1462,
            ShorterSignature = true,
        };

        yield return new DigitalSignatureParameters
        {
            DigitalSignatureAlgorithm = DigitalSignatureAlgorithm.FalconPadded512,
            LengthSecretKey = 1281,
            LengthPublicKey = 897,
            LengthSignature = 666,
            ShorterSignature = false,
        };

        yield return new DigitalSignatureParameters
        {
            DigitalSignatureAlgorithm = DigitalSignatureAlgorithm.FalconPadded1024,
            LengthSecretKey = 2305,
            LengthPublicKey = 1793,
            LengthSignature = 1280,
            ShorterSignature = false,
        };

        yield return new DigitalSignatureParameters
        {
            DigitalSignatureAlgorithm = DigitalSignatureAlgorithm.SphincsPlusSha2128f,
            LengthSecretKey = 64,
            LengthPublicKey = 32,
            LengthSignature = 17088,
            ShorterSignature = false,
        };

        yield return new DigitalSignatureParameters
        {
            DigitalSignatureAlgorithm = DigitalSignatureAlgorithm.SphincsPlusSha2192f,
            LengthSecretKey = 96,
            LengthPublicKey = 48,
            LengthSignature = 35664,
            ShorterSignature = false,
        };

        yield return new DigitalSignatureParameters
        {
            DigitalSignatureAlgorithm = DigitalSignatureAlgorithm.SphincsPlusSha2256f,
            LengthSecretKey = 128,
            LengthPublicKey = 64,
            LengthSignature = 49856,
            ShorterSignature = false,
        };

        yield return new DigitalSignatureParameters
        {
            DigitalSignatureAlgorithm = DigitalSignatureAlgorithm.SphincsPlusShake128f,
            LengthSecretKey = 64,
            LengthPublicKey = 32,
            LengthSignature = 17088,
            ShorterSignature = false,
        };

        yield return new DigitalSignatureParameters
        {
            DigitalSignatureAlgorithm = DigitalSignatureAlgorithm.SphincsPlusShake192f,
            LengthSecretKey = 96,
            LengthPublicKey = 48,
            LengthSignature = 35664,
            ShorterSignature = false,
        };

        yield return new DigitalSignatureParameters
        {
            DigitalSignatureAlgorithm = DigitalSignatureAlgorithm.SphincsPlusShake256f,
            LengthSecretKey = 128,
            LengthPublicKey = 64,
            LengthSignature = 49856,
            ShorterSignature = false,
        };
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void GenerateKeyPair_Should_Return_Valid_KeyPair(DigitalSignatureParameters digitalSignatureParameters)
    {
        // Arrange
        var providerFactory = new DigitalSignatureProviderFactory();
        var provider = providerFactory.Create(digitalSignatureParameters.DigitalSignatureAlgorithm);

        // Act
        var keyPair = provider.GenerateKeyPair();

        // Assert
        Assert.That(keyPair, Is.Not.Null);
        Assert.That(keyPair.PublicKey.Value, Is.Not.Null.And.Not.Empty);
        Assert.That(keyPair.PrivateKey.Value, Is.Not.Null);

        Assert.That(keyPair.PublicKey.Value.Length, Is.EqualTo(digitalSignatureParameters.LengthPublicKey));
        Assert.That(keyPair.PrivateKey.Value.Length, Is.EqualTo(digitalSignatureParameters.LengthSecretKey));
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void Sign_Should_Return_Valid_Signature(DigitalSignatureParameters digitalSignatureParameters)
    {
        // Arrange
        var providerFactory = new DigitalSignatureProviderFactory();
        var provider = providerFactory.Create(digitalSignatureParameters.DigitalSignatureAlgorithm);
        var keyPair = provider.GenerateKeyPair();
        var message = CreateRandomMessage(256);

        // Act
        var signature = provider.Sign(message, keyPair.PrivateKey);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Value, Is.Not.Null.And.Not.Empty);

        if (digitalSignatureParameters.ShorterSignature)
        {
            Assert.That(signature.Value.Length, Is.LessThanOrEqualTo(digitalSignatureParameters.LengthSignature));
        }
        else
        {
            Assert.That(signature.Value.Length, Is.EqualTo(digitalSignatureParameters.LengthSignature));
        }
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void Verify_With_Valid_Signature_Should_Return_True(DigitalSignatureParameters digitalSignatureParameters)
    {
        // Arrange
        var providerFactory = new DigitalSignatureProviderFactory();
        var provider = providerFactory.Create(digitalSignatureParameters.DigitalSignatureAlgorithm);
        var keyPair = provider.GenerateKeyPair();
        var message = CreateRandomMessage(256);
        var signature = provider.Sign(message, keyPair.PrivateKey);

        // Act
        var result = provider.Verify(message, signature, keyPair.PublicKey);

        // Assert
        Assert.That(result, Is.True);
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void Verify_With_Tampered_Message_Should_Return_False(DigitalSignatureParameters digitalSignatureParameters)
    {
        // Arrange
        var providerFactory = new DigitalSignatureProviderFactory();
        var provider = providerFactory.Create(digitalSignatureParameters.DigitalSignatureAlgorithm);
        var keyPair = provider.GenerateKeyPair();
        var originalMessage = CreateRandomMessage(256);
        var signature = provider.Sign(originalMessage, keyPair.PrivateKey);

        var tamperedBytes = originalMessage.Value.ToArray();
        tamperedBytes[0] ^= 0xFF; // Change one byte
        var tamperedMessage = new Message(tamperedBytes);

        // Act && Assert
        Assert.Throws<CryptographicException>(() => provider.Verify(tamperedMessage, signature, keyPair.PublicKey));
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void Sign_With_Null_Message_Should_Throw_ArgumentNullException(DigitalSignatureParameters digitalSignatureParameters)
    {
        // Arrange
        var providerFactory = new DigitalSignatureProviderFactory();
        var provider = providerFactory.Create(digitalSignatureParameters.DigitalSignatureAlgorithm);
        var keyPair = provider.GenerateKeyPair();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => provider.Sign(null!, keyPair.PrivateKey));
    }

    [TestCaseSource(nameof(GenerateTestCasesParameters))]
    public void Sign_With_Null_PrivateKey_Should_Throw_ArgumentNullException(DigitalSignatureParameters digitalSignatureParameters)
    {
        // Arrange
        var providerFactory = new DigitalSignatureProviderFactory();
        var provider = providerFactory.Create(digitalSignatureParameters.DigitalSignatureAlgorithm);
        var message = CreateRandomMessage(256);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => provider.Sign(message, privateKey: null));
    }

    private static IMessage CreateRandomMessage(int size)
    {
        var bytes = new byte[size];
        RandomNumberGenerator.Fill(bytes);

        return new Message(bytes);
    }
}

namespace PQCrypto.IO.Internal.Cryptography.libopq_0_15_0_1;

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using PQCrypto.IO.Extensions;

internal sealed class Falcon1024Provider : IDigitalSignatureProvider
{
    private static readonly GenerateKeypair GenerateKeypairMethod;

    private static readonly int OQS_SIG_FALCON_CRYPTO_BYTES = 1462;
    private static readonly int OQS_SIG_FALCON_CRYPTO_PUBLICKEYBYTES = 1793;
    private static readonly int OQS_SIG_FALCON_CRYPTO_SECRETKEYBYTES = 2305;

    private static readonly Sign SignMethod;
    private static readonly Verify VerifyMethod;

    public DigitalSignatureAlgorithm DigitalSignatureAlgorithm { get; } = DigitalSignatureAlgorithm.Falcon1024;
    public LibVersion LibVersion { get; } = LibVersion.libopq_0_15_0_1;

    static Falcon1024Provider()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            GenerateKeypairMethod = Windows.OQS_SIG_falcon_1024_keypair;
            SignMethod = Windows.OQS_SIG_falcon_1024_sign;
            VerifyMethod = Windows.OQS_SIG_falcon_1024_verify;

            return;
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            GenerateKeypairMethod = Linux.OQS_SIG_falcon_1024_keypair;
            SignMethod = Linux.OQS_SIG_falcon_1024_sign;
            VerifyMethod = Linux.OQS_SIG_falcon_1024_verify;

            return;
        }

        throw new PlatformNotSupportedException("liboqs native library not found or incompatible version.");
    }

    public IDigitalSignatureKeyPair GenerateKeyPair()
    {
        var publicKey = new byte[OQS_SIG_FALCON_CRYPTO_PUBLICKEYBYTES];
        var privateKey = new byte[OQS_SIG_FALCON_CRYPTO_SECRETKEYBYTES];

        var result = GenerateKeypairMethod(publicKey, privateKey);

        if (result is 0)
        {
            var keyPair = new DigitalSignatureKeyPair
            {
                DigitalSignatureAlgorithm = this.DigitalSignatureAlgorithm,
                PublicKey = new DigitalSignaturePublicKey(this.DigitalSignatureAlgorithm, this.LibVersion, publicKey),
                PrivateKey = new DigitalSignaturePrivateKey(this.DigitalSignatureAlgorithm, this.LibVersion, privateKey),
                LibVersion = this.LibVersion,
            };

            return keyPair;
        }

        throw new CryptographicException($"{this.DigitalSignatureAlgorithm} keypair generation failed.");
    }

    public IDigitalSignature Sign(in IMessage message, in IDigitalSignaturePrivateKey privateKey)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(privateKey);
        VersionMismatchException.ThrowIfVersionMismatch(this.LibVersion, privateKey.LibVersion);

        privateKey.Value.RequireExactLength(nameof(privateKey), OQS_SIG_FALCON_CRYPTO_SECRETKEYBYTES);

        var signature = new byte[OQS_SIG_FALCON_CRYPTO_BYTES];
        var signatureLen = new nuint(0);
        var messageLen = new nuint((uint)message.Value.Length);

        var apiResult = SignMethod(signature, ref signatureLen, message.Value, messageLen, privateKey.Value);

        if (apiResult != 0)
        {
            throw new CryptographicException($"{this.DigitalSignatureAlgorithm} signing failed with OQS error code: {apiResult}");
        }

        if (signatureLen.ToUInt32() > signature.Length)
        {
            throw new CryptographicException($"{this.DigitalSignatureAlgorithm} produced oversized signature: {signature.Length} bytes");
        }

        var signatureResult = new byte[signatureLen.ToUInt32()];
        Array.Copy(signature, signatureResult, signatureResult.Length);

        var result = new DigitalSignature(this.DigitalSignatureAlgorithm, this.LibVersion, signatureResult);

        return result;
    }

    public bool Verify(in IMessage message, in IDigitalSignature digitalSignature, in IDigitalSignaturePublicKey publicKey)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(digitalSignature);
        ArgumentNullException.ThrowIfNull(publicKey);
        VersionMismatchException.ThrowIfVersionMismatch(this.LibVersion, digitalSignature.LibVersion);
        VersionMismatchException.ThrowIfVersionMismatch(this.LibVersion, publicKey.LibVersion);

        publicKey.Value.RequireExactLength(nameof(publicKey), OQS_SIG_FALCON_CRYPTO_PUBLICKEYBYTES);

        var signatureLen = new nuint((uint)digitalSignature.Value.Length);
        var messageLen = new nuint((uint)message.Value.Length);

        var apiResult = VerifyMethod(message.Value, messageLen, digitalSignature.Value, signatureLen, publicKey.Value);

        if (apiResult == 0)
        {
            return true;
        }

        if (apiResult == 1)
        {
            return false;
        }

        throw new CryptographicException($"{this.DigitalSignatureAlgorithm} verification failed with OQS error code: {apiResult}");
    }

    private static class Linux
    {
        [DllImport(NativeLibraryPath.LINUX_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_SIG_falcon_1024_keypair(byte[] publicKey, byte[] secretKey);

        [DllImport(NativeLibraryPath.LINUX_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_SIG_falcon_1024_sign(byte[] signature, ref nuint signatureLen, byte[] message, nuint messageLen, byte[] secretKey);

        [DllImport(NativeLibraryPath.LINUX_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_SIG_falcon_1024_verify(byte[] message, nuint messageLen, byte[] signature, nuint signatureLen, byte[] publicKey);
    }

    private static class Windows
    {
        [DllImport(NativeLibraryPath.WINDOWS_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_SIG_falcon_1024_keypair(byte[] publicKey, byte[] secretKey);

        [DllImport(NativeLibraryPath.WINDOWS_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_SIG_falcon_1024_sign(byte[] signature, ref nuint signatureLen, byte[] message, nuint messageLen, byte[] secretKey);

        [DllImport(NativeLibraryPath.WINDOWS_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_SIG_falcon_1024_verify(byte[] message, nuint messageLen, byte[] signature, nuint signatureLen, byte[] publicKey);
    }
}

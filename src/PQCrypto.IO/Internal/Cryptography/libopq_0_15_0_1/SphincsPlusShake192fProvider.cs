namespace PQCrypto.IO.Internal.Cryptography.libopq_0_15_0_1;

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using PQCrypto.IO.Extensions;

internal sealed class SphincsPlusShake192fProvider : IDigitalSignatureProvider
{
    private static readonly GenerateKeypair GenerateKeypairMethod;

    private static readonly int OQS_SIG_SPHINCSSHAKE192_F_SIMPLE_CLEAN_CRYPTO_BYTES = 35664;
    private static readonly int OQS_SIG_SPHINCSSHAKE192_F_SIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES = 48;
    private static readonly int OQS_SIG_SPHINCSSHAKE192_F_SIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES = 96;

    private static readonly Sign SignMethod;
    private static readonly Verify VerifyMethod;

    public DigitalSignatureAlgorithm DigitalSignatureAlgorithm { get; } = DigitalSignatureAlgorithm.SphincsPlusShake192f;
    public LibVersion LibVersion { get; } = LibVersion.libopq_0_15_0_1;

    static SphincsPlusShake192fProvider()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            GenerateKeypairMethod = Windows.OQS_SIG_sphincs_shake_192f_simple_keypair;
            SignMethod = Windows.OQS_SIG_sphincs_shake_192f_simple_sign;
            VerifyMethod = Windows.OQS_SIG_sphincs_shake_192f_simple_verify;

            return;
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            GenerateKeypairMethod = Linux.OQS_SIG_sphincs_shake_192f_simple_keypair;
            SignMethod = Linux.OQS_SIG_sphincs_shake_192f_simple_sign;
            VerifyMethod = Linux.OQS_SIG_sphincs_shake_192f_simple_verify;

            return;
        }

        throw new PlatformNotSupportedException("liboqs native library not found or incompatible version.");
    }

    public IDigitalSignatureKeyPair GenerateKeyPair()
    {
        var publicKey = new byte[OQS_SIG_SPHINCSSHAKE192_F_SIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
        var privateKey = new byte[OQS_SIG_SPHINCSSHAKE192_F_SIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];

        var result = GenerateKeypairMethod(publicKey, privateKey);

        if (result is 0)
        {
            var keyPair = new DigitalSignatureKeyPair
            {
                DigitalSignatureAlgorithm = this.DigitalSignatureAlgorithm,
                PublicKey = new DigitalSignaturePublicKey(this.DigitalSignatureAlgorithm, publicKey, this.LibVersion),
                PrivateKey = new DigitalSignaturePrivateKey(this.DigitalSignatureAlgorithm, privateKey, this.LibVersion),
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

        privateKey.Value.RequireExactLength(nameof(privateKey), OQS_SIG_SPHINCSSHAKE192_F_SIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);

        var signature = new byte[OQS_SIG_SPHINCSSHAKE192_F_SIMPLE_CLEAN_CRYPTO_BYTES];
        var signatureLen = new nuint(0);
        var messageLen = new nuint((uint)message.Value.Length);

        var apiResult = SignMethod(signature, ref signatureLen, message.Value, messageLen, privateKey.Value);

        if (apiResult != 0)
        {
            throw new CryptographicException($"{this.DigitalSignatureAlgorithm} signing failed with OQS error code: {apiResult}");
        }

        if (signatureLen != (nuint)signature.Length)
        {
            throw new CryptographicException($"{this.DigitalSignatureAlgorithm} produced signature of unexpected length: {signatureLen} (expected {signature.Length})");
        }

        var result = new DigitalSignature(this.DigitalSignatureAlgorithm, this.LibVersion, signature);

        return result;
    }

    public bool Verify(in IMessage message, in IDigitalSignature digitalSignature, in IDigitalSignaturePublicKey publicKey)
    {
        VersionMismatchException.ThrowIfVersionMismatch(this.LibVersion, digitalSignature.LibVersion);
        VersionMismatchException.ThrowIfVersionMismatch(this.LibVersion, publicKey.LibVersion);
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(digitalSignature);
        ArgumentNullException.ThrowIfNull(publicKey);

        digitalSignature.Value.RequireExactLength(nameof(digitalSignature), OQS_SIG_SPHINCSSHAKE192_F_SIMPLE_CLEAN_CRYPTO_BYTES);
        publicKey.Value.RequireExactLength(nameof(publicKey), OQS_SIG_SPHINCSSHAKE192_F_SIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

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
        internal static extern int OQS_SIG_sphincs_shake_192f_simple_keypair(byte[] publicKey, byte[] secretKey);

        [DllImport(NativeLibraryPath.LINUX_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_SIG_sphincs_shake_192f_simple_sign(byte[] signature, ref nuint signatureLen, byte[] message, nuint messageLen, byte[] secretKey);

        [DllImport(NativeLibraryPath.LINUX_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_SIG_sphincs_shake_192f_simple_verify(byte[] message, nuint messageLen, byte[] signature, nuint signatureLen, byte[] publicKey);
    }

    private static class Windows
    {
        [DllImport(NativeLibraryPath.WINDOWS_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_SIG_sphincs_shake_192f_simple_keypair(byte[] publicKey, byte[] secretKey);

        [DllImport(NativeLibraryPath.WINDOWS_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_SIG_sphincs_shake_192f_simple_sign(byte[] signature, ref nuint signatureLen, byte[] message, nuint messageLen, byte[] secretKey);

        [DllImport(NativeLibraryPath.WINDOWS_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_SIG_sphincs_shake_192f_simple_verify(byte[] message, nuint messageLen, byte[] signature, nuint signatureLen, byte[] publicKey);
    }
}

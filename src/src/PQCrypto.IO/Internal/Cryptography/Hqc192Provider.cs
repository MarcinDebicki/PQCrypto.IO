namespace PQCrypto.IO.Internal.Cryptography;

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using PQCrypto.IO.Extensions;

internal sealed class Hqc192Provider : IKeyEncapsulationProvider
{
    private static readonly Decaps DecapsMethod;
    private static readonly Encaps EncapsMethod;
    private static readonly GenerateKeypair GenerateKeypairMethod;

    private static readonly int OQS_KEM_HQC_192_LENGTH_CIPHERTEXT = 8978;
    private static readonly int OQS_KEM_HQC_192_LENGTH_PUBLIC_KEY = 4522;
    private static readonly int OQS_KEM_HQC_192_LENGTH_SECRET_KEY = 4586;
    private static readonly int OQS_KEM_HQC_192_LENGTH_SHARED_SECRET = 64;

    public KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; } = KeyEncapsulationAlgorithm.Hqc192;

    static Hqc192Provider()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            DecapsMethod = Windows.OQS_KEM_hqc_192_decaps;
            EncapsMethod = Windows.OQS_KEM_hqc_192_encaps;
            GenerateKeypairMethod = Windows.OQS_KEM_hqc_192_keypair;

            return;
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            DecapsMethod = Linux.OQS_KEM_hqc_192_decaps;
            EncapsMethod = Linux.OQS_KEM_hqc_192_encaps;
            GenerateKeypairMethod = Linux.OQS_KEM_hqc_192_keypair;

            return;
        }

        throw new PlatformNotSupportedException("liboqs native library not found or incompatible version.");
    }

    public IKeyEncapsulationResult Decapsulation(in IKeyEncapsulationCiphertext keyEncapsulationCiphertext, in IKeyEncapsulationPrivateKey keyEncapsulationPrivateKey)
    {
        ArgumentNullException.ThrowIfNull(keyEncapsulationCiphertext);
        ArgumentNullException.ThrowIfNull(keyEncapsulationPrivateKey);

        keyEncapsulationCiphertext.Value.RequireExactLength(nameof(keyEncapsulationCiphertext), OQS_KEM_HQC_192_LENGTH_CIPHERTEXT);
        keyEncapsulationPrivateKey.Value.RequireExactLength(nameof(keyEncapsulationPrivateKey), OQS_KEM_HQC_192_LENGTH_SECRET_KEY);

        var plainSessionKey = new byte[OQS_KEM_HQC_192_LENGTH_SHARED_SECRET];

        var apiResult = DecapsMethod(plainSessionKey, keyEncapsulationCiphertext.Value, keyEncapsulationPrivateKey.Value);

        if (apiResult == 0)
        {
            var sessionKey = new KeyEncapsulationResult
            {
                KeyEncapsulationAlgorithm = this.KeyEncapsulationAlgorithm,
                KeyEncapsulationCiphertext = keyEncapsulationCiphertext,
                KeyEncapsulationSharedSecret = new KeyEncapsulationSharedSecret(this.KeyEncapsulationAlgorithm, plainSessionKey),
            };

            return sessionKey;
        }

        throw new CryptographicException($"{this.KeyEncapsulationAlgorithm} decapsulation failed.");
    }

    public IKeyEncapsulationResult Encapsulation(in IKeyEncapsulationPublicKey publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        publicKey.Value.RequireExactLength(nameof(publicKey), OQS_KEM_HQC_192_LENGTH_PUBLIC_KEY);

        var secretSessionKey = new byte[OQS_KEM_HQC_192_LENGTH_CIPHERTEXT];
        var plainSessionKey = new byte[OQS_KEM_HQC_192_LENGTH_SHARED_SECRET];

        var apiResult = EncapsMethod(secretSessionKey, plainSessionKey, publicKey.Value);

        if (apiResult == 0)
        {
            var sessionKey = new KeyEncapsulationResult
            {
                KeyEncapsulationAlgorithm = this.KeyEncapsulationAlgorithm,
                KeyEncapsulationCiphertext = new KeyEncapsulationCiphertext(this.KeyEncapsulationAlgorithm, secretSessionKey),
                KeyEncapsulationSharedSecret = new KeyEncapsulationSharedSecret(this.KeyEncapsulationAlgorithm, plainSessionKey),
            };

            return sessionKey;
        }

        throw new CryptographicException($"{this.KeyEncapsulationAlgorithm} encapsulation failed.");
    }

    public IKeyEncapsulationKeyPair GenerateKeyPair()
    {
        var publicKey = new byte[OQS_KEM_HQC_192_LENGTH_PUBLIC_KEY];
        var privateKey = new byte[OQS_KEM_HQC_192_LENGTH_SECRET_KEY];

        var apiResult = GenerateKeypairMethod(publicKey, privateKey);

        if (apiResult == 0)
        {
            var keyPair = new KeyEncapsulationKeyPair
            {
                KeyEncapsulationAlgorithm = this.KeyEncapsulationAlgorithm,
                PublicKey = new KeyEncapsulationPublicKey(this.KeyEncapsulationAlgorithm, publicKey),
                PrivateKey = new KeyEncapsulationPrivateKey(this.KeyEncapsulationAlgorithm, privateKey),
            };

            return keyPair;
        }

        throw new CryptographicException($"{this.KeyEncapsulationAlgorithm} keypair generation failed.");
    }

    private static class Linux
    {
        [DllImport(NativeLibraryPath.LINUX_PATH, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_KEM_hqc_192_decaps(byte[] plainSessionKey, byte[] secretSessionKey, byte[] privateKey);

        [DllImport(NativeLibraryPath.LINUX_PATH, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_KEM_hqc_192_encaps(byte[] secretSessionKey, byte[] plainSessionKey, byte[] publicKey);

        [DllImport(NativeLibraryPath.LINUX_PATH, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_KEM_hqc_192_keypair(byte[] publicKey, byte[] privateKey);
    }

    private static class Windows
    {
        [DllImport(NativeLibraryPath.WINDOWS_PATH, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_KEM_hqc_192_decaps(byte[] plainSessionKey, byte[] secretSessionKey, byte[] privateKey);

        [DllImport(NativeLibraryPath.WINDOWS_PATH, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_KEM_hqc_192_encaps(byte[] secretSessionKey, byte[] plainSessionKey, byte[] publicKey);

        [DllImport(NativeLibraryPath.WINDOWS_PATH, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_KEM_hqc_192_keypair(byte[] publicKey, byte[] privateKey);
    }
}

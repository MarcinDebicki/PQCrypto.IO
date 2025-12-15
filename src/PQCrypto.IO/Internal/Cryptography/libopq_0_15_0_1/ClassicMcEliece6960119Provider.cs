namespace PQCrypto.IO.Internal.Cryptography.libopq_0_15_0_1;

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using PQCrypto.IO.Extensions;

internal sealed class ClassicMcEliece6960119Provider : IKeyEncapsulationProvider
{
    private const string DYNAMIC_OQS_LIB = nameof(DYNAMIC_OQS_LIB);

    private static readonly Decaps DecapsMethod;
    private static readonly Encaps EncapsMethod;
    private static readonly GenerateKeypair GenerateKeypairMethod;

    private static readonly int OQS_KEM_CLASSIC_MCELIECE_6960119_LENGTH_CIPHERTEXT = 194;
    private static readonly int OQS_KEM_CLASSIC_MCELIECE_6960119_LENGTH_PUBLIC_KEY = 1047319;
    private static readonly int OQS_KEM_CLASSIC_MCELIECE_6960119_LENGTH_SECRET_KEY = 13948;
    private static readonly int OQS_KEM_CLASSIC_MCELIECE_6960119_LENGTH_SHARED_SECRET = 32;

    public KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; } = KeyEncapsulationAlgorithm.ClassicMcEliece6960119;
    public LibVersion LibVersion { get; } = LibVersion.libopq_0_15_0_1;

    static ClassicMcEliece6960119Provider()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            DecapsMethod = Windows.OQS_KEM_classic_mceliece_6960119_decaps;
            EncapsMethod = Windows.OQS_KEM_classic_mceliece_6960119_encaps;
            GenerateKeypairMethod = Windows.OQS_KEM_classic_mceliece_6960119_keypair;

            return;
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            DecapsMethod = Linux.OQS_KEM_classic_mceliece_6960119_decaps;
            EncapsMethod = Linux.OQS_KEM_classic_mceliece_6960119_encaps;
            GenerateKeypairMethod = Linux.OQS_KEM_classic_mceliece_6960119_keypair;

            return;
        }

        throw new PlatformNotSupportedException("liboqs native library not found or incompatible version.");
    }

    public IKeyEncapsulationResult Decapsulation(in IKeyEncapsulationCiphertext keyEncapsulationCiphertext, in IKeyEncapsulationPrivateKey keyEncapsulationPrivateKey)
    {
        ArgumentNullException.ThrowIfNull(keyEncapsulationCiphertext);
        ArgumentNullException.ThrowIfNull(keyEncapsulationPrivateKey);
        VersionMismatchException.ThrowIfVersionMismatch(this.LibVersion, keyEncapsulationCiphertext.LibVersion);
        VersionMismatchException.ThrowIfVersionMismatch(this.LibVersion, keyEncapsulationPrivateKey.LibVersion);

        keyEncapsulationCiphertext.Value.RequireExactLength(nameof(keyEncapsulationCiphertext), OQS_KEM_CLASSIC_MCELIECE_6960119_LENGTH_CIPHERTEXT);
        keyEncapsulationPrivateKey.Value.RequireExactLength(nameof(keyEncapsulationPrivateKey), OQS_KEM_CLASSIC_MCELIECE_6960119_LENGTH_SECRET_KEY);

        var plainSessionKey = new byte[OQS_KEM_CLASSIC_MCELIECE_6960119_LENGTH_SHARED_SECRET];

        var apiResult = DecapsMethod(plainSessionKey, keyEncapsulationCiphertext.Value, keyEncapsulationPrivateKey.Value);

        if (apiResult == 0)
        {
            var sessionKey = new KeyEncapsulationResult
            {
                KeyEncapsulationAlgorithm = this.KeyEncapsulationAlgorithm,
                KeyEncapsulationCiphertext = keyEncapsulationCiphertext,
                KeyEncapsulationSharedSecret = new KeyEncapsulationSharedSecret(this.KeyEncapsulationAlgorithm, this.LibVersion, plainSessionKey),
                LibVersion = this.LibVersion,
            };

            return sessionKey;
        }

        throw new CryptographicException($"{this.KeyEncapsulationAlgorithm} decapsulation failed.");
    }

    public IKeyEncapsulationResult Encapsulation(in IKeyEncapsulationPublicKey publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        VersionMismatchException.ThrowIfVersionMismatch(this.LibVersion, publicKey.LibVersion);

        publicKey.Value.RequireExactLength(nameof(publicKey), OQS_KEM_CLASSIC_MCELIECE_6960119_LENGTH_PUBLIC_KEY);

        var secretSessionKey = new byte[OQS_KEM_CLASSIC_MCELIECE_6960119_LENGTH_CIPHERTEXT];
        var plainSessionKey = new byte[OQS_KEM_CLASSIC_MCELIECE_6960119_LENGTH_SHARED_SECRET];

        var apiResult = EncapsMethod(secretSessionKey, plainSessionKey, publicKey.Value);

        if (apiResult == 0)
        {
            var sessionKey = new KeyEncapsulationResult
            {
                KeyEncapsulationAlgorithm = this.KeyEncapsulationAlgorithm,
                KeyEncapsulationCiphertext = new KeyEncapsulationCiphertext(this.KeyEncapsulationAlgorithm, this.LibVersion, secretSessionKey),
                KeyEncapsulationSharedSecret = new KeyEncapsulationSharedSecret(this.KeyEncapsulationAlgorithm, this.LibVersion, plainSessionKey),
                LibVersion = this.LibVersion,
            };

            return sessionKey;
        }

        throw new CryptographicException($"{this.KeyEncapsulationAlgorithm} encapsulation failed.");
    }

    public IKeyEncapsulationKeyPair GenerateKeyPair()
    {
        var publicKey = new byte[OQS_KEM_CLASSIC_MCELIECE_6960119_LENGTH_PUBLIC_KEY];
        var privateKey = new byte[OQS_KEM_CLASSIC_MCELIECE_6960119_LENGTH_SECRET_KEY];

        var apiResult = GenerateKeypairMethod(publicKey, privateKey);

        if (apiResult is 0)
        {
            var result = new KeyEncapsulationKeyPair
            {
                KeyEncapsulationAlgorithm = this.KeyEncapsulationAlgorithm,
                PrivateKey = new KeyEncapsulationPrivateKey(this.KeyEncapsulationAlgorithm, privateKey, this.LibVersion),
                PublicKey = new KeyEncapsulationPublicKey(this.KeyEncapsulationAlgorithm, publicKey, this.LibVersion),
                LibVersion = this.LibVersion,
            };

            return result;
        }

        throw new CryptographicException($"{this.KeyEncapsulationAlgorithm} keypair generation failed.");
    }

    private static class Linux
    {
        [DllImport(NativeLibraryPath.LINUX_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_KEM_classic_mceliece_6960119_decaps(byte[] plainSessionKey, byte[] secretSessionKey, byte[] privateKey);

        [DllImport(NativeLibraryPath.LINUX_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_KEM_classic_mceliece_6960119_encaps(byte[] secretSessionKey, byte[] plainSessionKey, byte[] publicKey);

        [DllImport(NativeLibraryPath.LINUX_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_KEM_classic_mceliece_6960119_keypair(byte[] publicKey, byte[] privateKey);
    }

    private static class Windows
    {
        [DllImport(NativeLibraryPath.WINDOWS_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_KEM_classic_mceliece_6960119_decaps(byte[] plainSessionKey, byte[] secretSessionKey, byte[] privateKey);

        [DllImport(NativeLibraryPath.WINDOWS_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_KEM_classic_mceliece_6960119_encaps(byte[] secretSessionKey, byte[] plainSessionKey, byte[] publicKey);

        [DllImport(NativeLibraryPath.WINDOWS_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_KEM_classic_mceliece_6960119_keypair(byte[] publicKey, byte[] privateKey);
    }
}

namespace PQCrypto.IO.Internal.Cryptography.libopq_0_15_0_1;

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using PQCrypto.IO.Extensions;

internal sealed class Hqc128Provider : IKeyEncapsulationProvider
{
    private static readonly Decaps DecapsMethod;
    private static readonly Encaps EncapsMethod;
    private static readonly GenerateKeypair GenerateKeypairMethod;

    private static readonly int OQS_KEM_HQC_128_LENGTH_CIPHERTEXT = 4433;
    private static readonly int OQS_KEM_HQC_128_LENGTH_PUBLIC_KEY = 2249;
    private static readonly int OQS_KEM_HQC_128_LENGTH_SECRET_KEY = 2305;
    private static readonly int OQS_KEM_HQC_128_LENGTH_SHARED_SECRET = 64;

    public KeyEncapsulationAlgorithm KeyEncapsulationAlgorithm { get; } = KeyEncapsulationAlgorithm.Hqc128;
    public LibVersion LibVersion { get; } = LibVersion.libopq_0_15_0_1;

    static Hqc128Provider()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            DecapsMethod = Windows.OQS_KEM_hqc_128_decaps;
            EncapsMethod = Windows.OQS_KEM_hqc_128_encaps;
            GenerateKeypairMethod = Windows.OQS_KEM_hqc_128_keypair;

            return;
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            DecapsMethod = Linux.OQS_KEM_hqc_128_decaps;
            EncapsMethod = Linux.OQS_KEM_hqc_128_encaps;
            GenerateKeypairMethod = Linux.OQS_KEM_hqc_128_keypair;

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

        keyEncapsulationCiphertext.Value.RequireExactLength(nameof(keyEncapsulationCiphertext), OQS_KEM_HQC_128_LENGTH_CIPHERTEXT);
        keyEncapsulationPrivateKey.Value.RequireExactLength(nameof(keyEncapsulationPrivateKey), OQS_KEM_HQC_128_LENGTH_SECRET_KEY);

        var plainSessionKeyMemorySafe = ProtectMemoryManager.Instance.Rent(OQS_KEM_HQC_128_LENGTH_SHARED_SECRET);
        var privateKeyMemorySafe = keyEncapsulationPrivateKey.Value;
        var apiResult = -1;

        using (plainSessionKeyMemorySafe.Acquire())
        using (privateKeyMemorySafe.Acquire())
        {
            apiResult = DecapsMethod(plainSessionKeyMemorySafe.Pointer, keyEncapsulationCiphertext.Value, privateKeyMemorySafe.Pointer);
        }

        if (apiResult == 0)
        {
            var sessionKey = new KeyEncapsulationResult
            {
                KeyEncapsulationAlgorithm = this.KeyEncapsulationAlgorithm,
                KeyEncapsulationCiphertext = keyEncapsulationCiphertext,
                KeyEncapsulationSharedSecret = new KeyEncapsulationSharedSecret(this.KeyEncapsulationAlgorithm, this.LibVersion, plainSessionKeyMemorySafe),
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

        publicKey.Value.RequireExactLength(nameof(publicKey), OQS_KEM_HQC_128_LENGTH_PUBLIC_KEY);

        var secretSessionKey = new byte[OQS_KEM_HQC_128_LENGTH_CIPHERTEXT];
        var plainSessionKeyMemorySafe = ProtectMemoryManager.Instance.Rent(OQS_KEM_HQC_128_LENGTH_SHARED_SECRET);
        var apiResult = -1;

        using (plainSessionKeyMemorySafe.Acquire())
        {
            apiResult = EncapsMethod(secretSessionKey, plainSessionKeyMemorySafe.Pointer, publicKey.Value);
        }

        if (apiResult == 0)
        {
            var sessionKey = new KeyEncapsulationResult
            {
                KeyEncapsulationAlgorithm = this.KeyEncapsulationAlgorithm,
                KeyEncapsulationCiphertext = new KeyEncapsulationCiphertext(this.KeyEncapsulationAlgorithm, this.LibVersion, secretSessionKey),
                KeyEncapsulationSharedSecret = new KeyEncapsulationSharedSecret(this.KeyEncapsulationAlgorithm, this.LibVersion, plainSessionKeyMemorySafe),
                LibVersion = this.LibVersion,
            };

            return sessionKey;
        }

        throw new CryptographicException($"{this.KeyEncapsulationAlgorithm} encapsulation failed.");
    }

    public IKeyEncapsulationKeyPair GenerateKeyPair()
    {
        var publicKey = new byte[OQS_KEM_HQC_128_LENGTH_PUBLIC_KEY];
        var privateKeyMemorySafe = ProtectMemoryManager.Instance.Rent(OQS_KEM_HQC_128_LENGTH_SECRET_KEY);
        var apiResult = -1;

        using (privateKeyMemorySafe.Acquire())
        {
            apiResult = GenerateKeypairMethod(publicKey, privateKeyMemorySafe.Pointer);
        }

        if (apiResult == 0)
        {
            var keyPair = new KeyEncapsulationKeyPair
            {
                KeyEncapsulationAlgorithm = this.KeyEncapsulationAlgorithm,
                PublicKey = new KeyEncapsulationPublicKey(this.KeyEncapsulationAlgorithm, this.LibVersion, publicKey),
                PrivateKey = new KeyEncapsulationPrivateKey(this.KeyEncapsulationAlgorithm, this.LibVersion, privateKeyMemorySafe),
                LibVersion = this.LibVersion,
            };

            return keyPair;
        }

        throw new CryptographicException($"{this.KeyEncapsulationAlgorithm} keypair generation failed.");
    }

    private static class Linux
    {
        [DllImport(NativeLibraryPath.LINUX_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_KEM_hqc_128_decaps(IntPtr plainSessionKey, byte[] secretSessionKey, IntPtr privateKey);

        [DllImport(NativeLibraryPath.LINUX_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_KEM_hqc_128_encaps(byte[] secretSessionKey, IntPtr plainSessionKey, byte[] publicKey);

        [DllImport(NativeLibraryPath.LINUX_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_KEM_hqc_128_keypair(byte[] publicKey, IntPtr privateKey);
    }

    private static class Windows
    {
        [DllImport(NativeLibraryPath.WINDOWS_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_KEM_hqc_128_decaps(IntPtr plainSessionKey, byte[] secretSessionKey, IntPtr privateKey);

        [DllImport(NativeLibraryPath.WINDOWS_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_KEM_hqc_128_encaps(byte[] secretSessionKey, IntPtr plainSessionKey, byte[] publicKey);

        [DllImport(NativeLibraryPath.WINDOWS_PATH_0_15_0_1, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OQS_KEM_hqc_128_keypair(byte[] publicKey, IntPtr privateKey);
    }
}

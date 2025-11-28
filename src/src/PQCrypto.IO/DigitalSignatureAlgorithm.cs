namespace PQCrypto.IO;

/// <summary>
///     Supported post-quantum digital signature algorithms.
/// </summary>
public enum DigitalSignatureAlgorithm
{
    // === CRYSTALS-Dilithium (ML-DSA) ===
    /// <summary>
    ///     CRYSTALS-Dilithium2
    ///     NIST security level 2 (~AES-128)
    ///     Signature size: 2 420 bytes, Public key: 1 312 bytes
    ///     Standardized as ML-DSA-44 in FIPS 204
    /// </summary>
    CrystalsDilithium2,

    /// <summary>
    ///     CRYSTALS-Dilithium3 (recommended for most use cases)
    ///     NIST security level 3 (~AES-192)
    ///     Signature size: 3 293 bytes, Public key: 1 952 bytes
    ///     Standardized as ML-DSA-65 in FIPS 204
    /// </summary>
    CrystalsDilithium3,

    /// <summary>
    ///     CRYSTALS-Dilithium5
    ///     NIST security level 5 (~AES-256)
    ///     Signature size: 4 595 bytes, Public key: 2 592 bytes
    ///     Standardized as ML-DSA-87 in FIPS 204
    /// </summary>
    CrystalsDilithium5,

    // === SPHINCS+ (SLH-DSA) – SHA2 variants ===
    /// <summary>
    ///     SPHINCS+-SHA2-128f (fast, NIST level 1)
    ///     Signature size: 16 976 bytes, Public key: 64 bytes
    ///     Standardized as SLH-DSA-SHA2-128f
    /// </summary>
    SphincsPlusSha2128f,

    /// <summary>
    ///     SPHINCS+-SHA2-192f (fast, NIST level 3)
    ///     Signature size: 35 600 bytes, Public key: 96 bytes
    ///     Standardized as SLH-DSA-SHA2-192f
    /// </summary>
    SphincsPlusSha2192f,

    /// <summary>
    ///     SPHINCS+-SHA2-256f (fast, NIST level 5)
    ///     Signature size: 49 856 bytes, Public key: 128 bytes
    ///     Standardized as SLH-DSA-SHA2-256f
    /// </summary>
    SphincsPlusSha2256f,

    // === SPHINCS+ (SLH-DSA) – SHAKE variants ===
    /// <summary>
    ///     SPHINCS+-SHAKE-128f (fast, NIST level 1)
    ///     Signature size: 16 976 bytes, Public key: 64 bytes
    ///     Standardized as SLH-DSA-SHAKE-128f
    /// </summary>
    SphincsPlusShake128f,

    /// <summary>
    ///     SPHINCS+-SHAKE-192f (fast, NIST level 3)
    ///     Signature size: 35 600 bytes, Public key: 96 bytes
    ///     Standardized as SLH-DSA-SHAKE-192f
    /// </summary>
    SphincsPlusShake192f,

    /// <summary>
    ///     SPHINCS+-SHAKE-256f (fast, NIST level 5)
    ///     Signature size: 49 856 bytes, Public key: 128 bytes
    ///     Standardized as SLH-DSA-SHAKE-256f
    /// </summary>
    SphincsPlusShake256f,

    // === Falcon (FN-DSA) ===
    /// <summary>
    ///     Falcon-512
    ///     NIST security level 1 (~AES-128)
    ///     Signature size: ~690–1280 bytes (variable), Public key: 897 bytes
    ///     Standardized as FN-DSA-512 in FIPS 205
    /// </summary>
    Falcon512,

    /// <summary>
    ///     Falcon-1024 (recommended for high security)
    ///     NIST security level 5 (~AES-256)
    ///     Signature size: ~1200–2300 bytes (variable), Public key: 1 793 bytes
    ///     Standardized as FN-DSA-1024 in FIPS 205
    /// </summary>
    Falcon1024,

    // === Padded variants – implementation only, not in the final NIST specification ===
    /// <summary>
    ///     Falcon-512 with padded NTT (legacy/reference implementation variant)
    ///     Identical security to Falcon512 – use Falcon512 instead
    /// </summary>
    FalconPadded512,

    /// <summary>
    ///     Falcon-1024 with padded NTT (legacy/reference implementation variant)
    ///     Identical security to Falcon1024 – use Falcon1024 instead
    /// </summary>
    FalconPadded1024,
}

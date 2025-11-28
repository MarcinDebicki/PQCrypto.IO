namespace PQCrypto.IO;

/// <summary>
///     Supported post-quantum Key encapsulation algorithms.
/// </summary>
public enum KeyEncapsulationAlgorithm
{
    None,

    // === CRYSTALS-Kyber ===
    /// <summary>
    ///     CRYSTALS-Kyber 512 (NIST security level 1, equivalent to AES-128)
    ///     Standardized as ML-KEM-512 in FIPS 203
    /// </summary>
    CrystalsKyber512,

    /// <summary>
    ///     CRYSTALS-Kyber 768 (NIST security level 3, equivalent to AES-192)
    ///     Standardized as ML-KEM-768 in FIPS 203
    /// </summary>
    CrystalsKyber768,

    /// <summary>
    ///     CRYSTALS-Kyber 1024 (NIST security level 5, equivalent to AES-256)
    ///     Standardized as ML-KEM-1024 in FIPS 203
    /// </summary>
    CrystalsKyber1024,

    // === HQC (Round 4 candidate – jeszcze nie standaryzowane) ===
    /// <summary>
    ///     HQC-128 (NIST security level 1, equivalent to AES-128)
    ///     Code-based KEM, NIST PQC Round 4 candidate
    /// </summary>
    Hqc128,

    /// <summary>
    ///     HQC-192 (NIST security level 3, equivalent to AES-192)
    ///     Code-based KEM, NIST PQC Round 4 candidate
    /// </summary>
    Hqc192,

    /// <summary>
    ///     HQC-256 (NIST security level 5, equivalent to AES-256)
    ///     Code-based KEM, NIST PQC Round 4 candidate
    /// </summary>
    Hqc256,

    // === Classic McEliece – dokładne parametry z oryginalnego submissionu ===
    /// <summary>
    ///     Classic McEliece 348864 (m=12, t=64)
    ///     NIST security level 1 (~AES-128)
    ///     Public key: 261 120 bytes, Ciphertext: 128 bytes
    ///     Extremely conservative, IND-CCA2 secure for over 40 years
    /// </summary>
    ClassicMcEliece348864,

    /// <summary>
    ///     Classic McEliece 460896 (m=13, t=64)
    ///     NIST security level 3 (~AES-192)
    ///     Public key: 524 160 bytes, Ciphertext: 144 bytes
    /// </summary>
    ClassicMcEliece460896,

    /// <summary>
    ///     Classic McEliece 6688128 (m=13, t=119)
    ///     NIST security level 5 (~AES-256)
    ///     Public key: 1 040 992 bytes (~1 MB), Ciphertext: 240 bytes
    /// </summary>
    ClassicMcEliece6688128,

    /// <summary>
    ///     Classic McEliece 6960119 (m=13, t=119)
    ///     NIST security level 5 (~AES-256)
    ///     Public key: 1 049 088 bytes (~1 MB), Ciphertext: 240 bytes
    /// </summary>
    ClassicMcEliece6960119,

    /// <summary>
    ///     Classic McEliece 8192128 (m=13, t=128)
    ///     NIST security level 5+ (significantly above AES-256)
    ///     Public key: 1 357 824 bytes (~1.3 MB), Ciphertext: 256 bytes
    ///     The biggest and safest option – “paranoia mode”
    /// </summary>
    ClassicMcEliece8192128,
}

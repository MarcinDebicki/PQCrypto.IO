namespace PQCrypto.IO.Internal;

using System.Collections.Concurrent;
using PQCrypto.IO.Internal.Cryptography.libopq_0_15_0_1;

/// <summary>
///     Factory for creating high-level post-quantum Key Encapsulation Mechanism (KEM) providers.
///     All supported algorithms are stateless — a new instance is returned on each call,
///     following the conventions of System.Security.Cryptography (RSA.Create(), ECDsa.Create(), etc.).
/// </summary>
public sealed class KeyEncapsulationProviderFactory : IKeyEncapsulationProviderFactory
{
    private static readonly ConcurrentDictionary<(KeyEncapsulationAlgorithm, LibVersion), IKeyEncapsulationProvider> PROVIDER_CACHE = new();

    public IKeyEncapsulationProvider Create(KeyEncapsulationAlgorithm algorithm, LibVersion version = LibVersion.libopq_0_15_0_1)
    {
        if (PROVIDER_CACHE.TryGetValue((algorithm, version), out var provider) is false)
        {
            provider = CreateProviderInstance(algorithm, version);
            PROVIDER_CACHE[(algorithm, version)] = provider;
        }

        return provider;
    }

    private static IKeyEncapsulationProvider CreateProviderInstance(KeyEncapsulationAlgorithm algorithm, LibVersion libVersion)
    {
        switch (libVersion)
        {
            case LibVersion.libopq_0_15_0_1: return CreateProviderInstance_0_15_0_1(algorithm);

            default:
                throw new NotSupportedException($"KEM version '{libVersion}' is not supported in this build.");
        }
    }

    private static IKeyEncapsulationProvider CreateProviderInstance_0_15_0_1(KeyEncapsulationAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case KeyEncapsulationAlgorithm.ClassicMcEliece348864:
                return new ClassicMcEliece348864Provider();
            case KeyEncapsulationAlgorithm.ClassicMcEliece460896:
                return new ClassicMcEliece460896Provider();
            case KeyEncapsulationAlgorithm.ClassicMcEliece6688128:
                return new ClassicMcEliece6688128Provider();
            case KeyEncapsulationAlgorithm.ClassicMcEliece6960119:
                return new ClassicMcEliece6960119Provider();
            case KeyEncapsulationAlgorithm.ClassicMcEliece8192128:
                return new ClassicMcEliece8192128Provider();

            case KeyEncapsulationAlgorithm.CrystalsKyber512:
                return new CrystalsKyber512Provider();
            case KeyEncapsulationAlgorithm.CrystalsKyber768:
                return new CrystalsKyber768Provider();
            case KeyEncapsulationAlgorithm.CrystalsKyber1024:
                return new CrystalsKyber1024Provider();

            case KeyEncapsulationAlgorithm.Hqc128:
                return new Hqc128Provider();
            case KeyEncapsulationAlgorithm.Hqc192:
                return new Hqc192Provider();
            case KeyEncapsulationAlgorithm.Hqc256:
                return new Hqc256Provider();

            default:
                throw new NotSupportedException($"KEM algorithm '{algorithm}' is not supported in this build.");
        }
    }
}

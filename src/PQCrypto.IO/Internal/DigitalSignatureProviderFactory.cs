namespace PQCrypto.IO.Internal;

using System.Collections.Concurrent;
using PQCrypto.IO.Internal.Cryptography.libopq_0_15_0_1;

/// <summary>
///     Factory for creating high-level post-quantum digital signature providers.
///     All supported algorithms are stateless — a new instance is returned on each call,
///     following the conventions of System.Security.Cryptography (RSA.Create(), ECDsa.Create(), etc.).
/// </summary>
public sealed class DigitalSignatureProviderFactory : IDigitalSignatureProviderFactory
{
    private static readonly ConcurrentDictionary<(DigitalSignatureAlgorithm, LibVersion), IDigitalSignatureProvider> PROVIDER_CACHE = new();

    public IDigitalSignatureProvider Create(DigitalSignatureAlgorithm algorithm, LibVersion libVersion = LibVersion.libopq_0_15_0_1)
    {
        if (PROVIDER_CACHE.TryGetValue((algorithm, libVersion), out var provider) is false)
        {
            provider = this.CreateProviderInstance(algorithm, libVersion);
            PROVIDER_CACHE[(algorithm, libVersion)] = provider;
        }

        return provider;
    }

    private IDigitalSignatureProvider? CreateProviderInstance(DigitalSignatureAlgorithm algorithm, LibVersion libVersion)
    {
        switch (libVersion)
        {
            case LibVersion.libopq_0_15_0_1:
                return CreateProviderInstance_0_15_0_1(algorithm);

            default:
                throw new NotSupportedException($"Liboqs version '{libVersion}' is not supported.");
        }
    }

    private static IDigitalSignatureProvider CreateProviderInstance_0_15_0_1(DigitalSignatureAlgorithm digitalSignatureAlgorithm)
    {
        switch (digitalSignatureAlgorithm)
        {
            case DigitalSignatureAlgorithm.CrystalsDilithium2:
                return new CrystalsDilithium2Provider();
            case DigitalSignatureAlgorithm.CrystalsDilithium3:
                return new CrystalsDilithium3Provider();
            case DigitalSignatureAlgorithm.CrystalsDilithium5:
                return new CrystalsDilithium5Provider();

            case DigitalSignatureAlgorithm.SphincsPlusSha2128f:
                return new SphincsPlusSha2128fProvider();
            case DigitalSignatureAlgorithm.SphincsPlusSha2192f:
                return new SphincsPlusSha2192fProvider();
            case DigitalSignatureAlgorithm.SphincsPlusSha2256f:
                return new SphincsPlusSha2256fProvider();
            case DigitalSignatureAlgorithm.SphincsPlusShake128f:
                return new SphincsPlusShake128fProvider();
            case DigitalSignatureAlgorithm.SphincsPlusShake192f:
                return new SphincsPlusShake192fProvider();
            case DigitalSignatureAlgorithm.SphincsPlusShake256f:
                return new SphincsPlusShake256fProvider();

            case DigitalSignatureAlgorithm.Falcon512:
                return new Falcon512Provider();
            case DigitalSignatureAlgorithm.Falcon1024:
                return new Falcon1024Provider();
            case DigitalSignatureAlgorithm.FalconPadded512:
                return new FalconPadded512Provider();
            case DigitalSignatureAlgorithm.FalconPadded1024:
                return new FalconPadded1024Provider();

            default:
                throw new NotSupportedException($"Digital signature algorithm '{digitalSignatureAlgorithm}' is not supported in this build.");
        }
    }
}

namespace PQCrypto.IO;

public interface IDigitalSignatureProviderFactory
{
    IDigitalSignatureProvider Create(DigitalSignatureAlgorithm digitalSignatureAlgorithm, LibVersion libVersion = LibVersion.libopq_0_15_0_1);
}

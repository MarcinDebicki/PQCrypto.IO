namespace PQCrypto.IO;

public interface IDigitalSignatureProviderFactory
{
    IDigitalSignatureProvider Create(DigitalSignatureAlgorithm digitalSignatureAlgorithm);
}

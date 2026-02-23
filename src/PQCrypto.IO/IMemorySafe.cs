namespace PQCrypto.IO;

public interface aaIMemorySafe : IDisposable
{
    int Length { get; }
    IntPtr Pointer { get; }
    Span<byte> AsSpan();

    bool Lock();
    void LockWait();
    void Unlock();
}

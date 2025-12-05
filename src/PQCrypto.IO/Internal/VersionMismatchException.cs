namespace PQCrypto.IO.Internal;

using System.Diagnostics;

public sealed class VersionMismatchException : Exception
{
    public VersionMismatchException()
    {
    }

    [StackTraceHidden]
    public static void ThrowIfVersionMismatch(LibVersion expected, LibVersion current)
    {
        if (expected != current)
        {
            throw new VersionMismatchException();
        }
    }
}

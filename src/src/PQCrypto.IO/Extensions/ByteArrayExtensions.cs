namespace PQCrypto.IO.Extensions;

using System.Diagnostics;
using PQCrypto.IO.Internal;

internal static class ByteArrayExtensions
{
    [StackTraceHidden]
    public static void RequireExactLength(this byte[] value, string field, int expectedLength)
    {
        if (value.Length == expectedLength)
        {
            return;
        }

        throw new WrongByteArrayLengthException(field, expectedLength);
    }
}

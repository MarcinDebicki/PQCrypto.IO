namespace PQCrypto.IO.Internal.Cryptography;

using System.Runtime.InteropServices;

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate int GenerateKeypair(byte[] publicKey, IntPtr secretKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate int Decaps(IntPtr plainSessionKey, byte[] secretSessionKey, IntPtr privateKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate int Encaps(byte[] secretSessionKey, IntPtr plainSessionKey, byte[] publicKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate int Sign(byte[] signature, ref nuint signatureLen, byte[] message, nuint messageLen, IntPtr secretKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate int Verify(byte[] message, nuint messageLen, byte[] signature, nuint signatureLen, byte[] publicKey);

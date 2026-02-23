namespace PQCrypto.IO.Internal;

using System.Runtime.InteropServices;

/// <summary>
///     secedit /export /cfg secedit.cfg
///     SeLockMemoryPrivilege=user1,user2,group3
///     secedit /configure /db secedit.sdb /cfg secedit.cfg /areas USER_RIGHTS
/// </summary>
public unsafe class ProtectMemory : IDisposable
{
    private readonly object sync = new();
    private IntPtr basePtr;
    private bool hibernateActive = false;
    private List<MemoryRegion> regions = new();
    private int totalSize;
    private int usedSize;

    public ProtectMemory(int initialSize)
    {
        this.totalSize = initialSize;
        this.usedSize = 0;

        // Platform-agnostic allocation
        this.basePtr = AllocateProtectedMemory(initialSize);

        if (this.basePtr == IntPtr.Zero)
        {
            throw new OutOfMemoryException("Cannot allocate protected memory.");
        }

        this.regions.Add(new MemoryRegion
        {
            Ptr = this.basePtr,
            Size = this.totalSize,
            Free = true,
            Owner = null,
            hibernateClear = false,
        });
    }

    public void Dispose()
    {
        if (OperatingSystem.IsWindows())
        {
            VirtualUnlock(this.basePtr, this.totalSize);
            VirtualFree(this.basePtr, dwSize: 0, dwFreeType: 0x8000);
        }
        else if (OperatingSystem.IsLinux())
        {
            munmap(this.basePtr, (UIntPtr)this.totalSize);
        }

        this.basePtr = IntPtr.Zero;
    }

    public MemorySafe Allocate(int size)
    {
        var bytes = new byte[size];

        return this.Allocate(bytes);
    }

    public MemorySafe Allocate(byte[] buffer)
    {
        return this.Allocate(new Span<byte>(buffer));
    }

    public MemorySafe Allocate(Span<byte> buffer)
    {
        if (this.hibernateActive is true)
        {
            throw new OperationCanceledException("Memory allocation canceled due to pending hibernation.");
        }

        lock (this.sync)
        {
            var index = this.FindFreeRegionIndex(buffer.Length);

            if (index < 0)
            {
                this.Compact();
                index = this.FindFreeRegionIndex(buffer.Length);

                if (index < 0)
                {
                    throw new OutOfMemoryException();
                }
            }

            var region = this.regions[index];

            if (region.Size > buffer.Length)
            {
                var newRegion = new MemoryRegion
                {
                    Ptr = region.Ptr + buffer.Length,
                    Size = region.Size - buffer.Length,
                    Free = true,
                    Owner = null,
                    hibernateClear = false,
                };

                region.Size = buffer.Length;
                this.regions.Insert(index + 1, newRegion);
            }

            region.Free = false;

            var mem = new MemorySafe(region.Ptr, region.Size, this);
            region.Owner = mem;

            this.regions[index] = region;

            buffer.CopyTo(new Span<byte>((void*)region.Ptr, region.Size));

            this.usedSize += region.Size;

            return mem;
        }
    }

    public void ClearAllBuffers()
    {
        this.hibernateActive = true;
        List<MemorySafe> toZero = new();

        foreach (var region in this.regions)
        {
            if (!region.Free && region.Owner.Lock())
            {
                toZero.Add(region.Owner);
            }
        }

        lock (this.sync)
        {
            foreach (var region in this.regions)
            {
                if (!region.Free && !toZero.Contains(region.Owner))
                {
                    region.Owner.LockWait();
                    toZero.Add(region.Owner);
                }
            }
        }

        foreach (var mem in toZero)
        {
            mem.AsSpan().Clear();
        }
    }

    public void Free(MemorySafe mem)
    {
        lock (this.sync)
        {
            var index = this.regions.FindIndex(r => r.Owner == mem);

            if (index < 0)
            {
                return;
            }

            var region = this.regions[index];

            region.Free = true;
            region.Owner = null;

            new Span<byte>((void*)region.Ptr, region.Size).Clear();

            this.usedSize -= region.Size;

            this.regions[index] = region;

            this.MergeAdjacent(index);
        }
    }

    /// <summary>
    ///     Rescue method — attempts to block all unlocked regions and move data to make space.
    /// </summary>
    private void Compact()
    {
        var i = 0;
        var max = this.regions.Count - 1;

        while (i < max)
        {
            var left = this.regions[i];
            var right = this.regions[i + 1];

            if (left.Free && !right.Free)
            {
                if (right.Owner.Lock())
                {
                    try
                    {
                        // Safe buffer copy
                        if (left.Size >= right.Size)
                        {
                            Buffer.MemoryCopy(
                                (void*)right.Ptr,
                                (void*)left.Ptr,
                                right.Size,
                                right.Size);
                        }
                        else
                        {
                            new Span<byte>((void*)right.Ptr, right.Size).CopyTo(new Span<byte>((void*)left.Ptr, right.Size));
                        }

                        // update used block
                        right.Owner.ptr = left.Ptr;
                        right.Ptr = left.Ptr;

                        // update free block
                        left.Ptr += right.Size;

                        // swap used and free in the collection
                        this.regions[i] = right;
                        this.regions[i + 1] = left;

                        // If the next block is also free to merge
                        if (i + 2 < this.regions.Count && this.regions[i + 2].Free)
                        {
                            var nextFree = this.regions[i + 2];

                            left.Size += nextFree.Size;
                            this.regions[i + 1] = left;
                            this.regions.RemoveAt(i + 2);
                            max--;
                        }
                    }
                    finally
                    {
                        right.Owner.Unlock();
                    }
                }
            }

            i++;
        }
    }

    private int FindFreeRegionIndex(int size)
    {
        for (var i = 0; i < this.regions.Count; i++)
        {
            if (this.regions[i].Free && this.regions[i].Size >= size)
            {
                return i;
            }
        }

        return -1;
    }

    private struct MemoryRegion
    {
        public IntPtr Ptr;
        public int Size;
        public bool Free;
        public MemorySafe Owner;
        public bool hibernateClear { get; set; }
    }

    private void MergeAdjacent(int index)
    {
        // scal w lewo
        if (index > 0 && this.regions[index - 1].Free)
        {
            var left = this.regions[index - 1];
            var current = this.regions[index];

            left.Size += current.Size;
            this.regions[index - 1] = left;
            this.regions.RemoveAt(index);
            index--;
        }

        // scal w prawo
        if (index < this.regions.Count - 1 && this.regions[index + 1].Free)
        {
            var current = this.regions[index];
            var right = this.regions[index + 1];

            current.Size += right.Size;
            this.regions[index] = current;
            this.regions.RemoveAt(index + 1);
        }
    }

    #region Platform-specific memory allocation

    private static IntPtr AllocateProtectedMemory(int size)
    {
        if (OperatingSystem.IsWindows())
        {
            return AllocateWindows(size);
        }
        else if (OperatingSystem.IsLinux())
        {
            return AllocateLinux(size);
        }
        else
        {
            throw new PlatformNotSupportedException("ProtectMemory is supported only on Windows and Linux.");
        }
    }

    // Windows
    private static IntPtr AllocateWindows(int size)
    {
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_READWRITE = 0x04;

        var ptr = VirtualAlloc(IntPtr.Zero, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (ptr == IntPtr.Zero)
        {
            Console.WriteLine("Nie przydzieliło pamięci");

            return IntPtr.Zero;
        }

        if (!VirtualLock(ptr, size))
        {
            Console.WriteLine("Nie zablokowało pamięci");
            VirtualFree(ptr, dwSize: 0, dwFreeType: 0x8000 /* MEM_RELEASE */);

            return IntPtr.Zero;
        }

        return ptr;
    }

    // Linux
    private static IntPtr AllocateLinux(int size)
    {
        const int PROT_READ = 0x1;
        const int PROT_WRITE = 0x2;
        const int MAP_PRIVATE = 0x02;
        const int MAP_ANONYMOUS = 0x20;

        var ptr = mmap(IntPtr.Zero, (UIntPtr)size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, fd: -1, offset: 0);

        if (ptr == new IntPtr(-1))
        {
            return IntPtr.Zero;
        }

        if (mlock(ptr, (UIntPtr)size) != 0)
        {
            munmap(ptr, (UIntPtr)size);

            return IntPtr.Zero;
        }

        return ptr;
    }

    #region WinAPI

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualLock(IntPtr lpAddress, int dwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFree(IntPtr lpAddress, int dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualUnlock(IntPtr lpAddress, int dwSize);

    #endregion

    #region Linux native

    [DllImport("libc", SetLastError = true)]
    private static extern IntPtr mmap(IntPtr addr, UIntPtr length, int prot, int flags, int fd, long offset);

    [DllImport("libc", SetLastError = true)]
    private static extern int mlock(IntPtr addr, UIntPtr len);

    [DllImport("libc", SetLastError = true)]
    private static extern int munmap(IntPtr addr, UIntPtr length);

    #endregion

    #endregion
}

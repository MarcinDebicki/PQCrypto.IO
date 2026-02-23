namespace PQCrypto.IO.Tests.Internal;

using NUnit.Framework;
using PQCrypto.IO.Internal;

[NonParallelizable]
[TestFixture]
public unsafe class ProtectMemoryTests
{
    [Test]
    public void Allocate_ShouldCreateMemorySafe_WithCorrectLength()
    {
        // Arrange
        using var protect = new ProtectMemory(1024);

        // Act
        var mem = protect.Allocate(100);

        // Assert
        Assert.That(mem, Is.Not.Null);
        Assert.That(mem.Length, Is.EqualTo(100));

        using (mem.Acquire())
        {
            var span = mem.AsSpan();
            Assert.That(span.Length, Is.EqualTo(100));
        }

        // Cleanup
        mem.Dispose();
    }

    [Test]
    public void Allocate_WithBuffer_ShouldCopyData()
    {
        // Arrange
        using var protect = new ProtectMemory(1024);

        var input = Enumerable.Range(start: 0, count: 50).Select(i => (byte)i).ToArray();

        // Act
        var mem = protect.Allocate(input);

        // Assert
        using (mem.Acquire())
        {
            var span = mem.AsSpan();

            for (var i = 0; i < input.Length; i++)
            {
                Assert.That(span[i], Is.EqualTo(input[i]));
            }
        }

        // Cleanup
        mem.Dispose();
    }

    [Test]
    public void Free_ShouldAllowReallocateSameSize()
    {
        // Arrange
        using var protect = new ProtectMemory(256);

        var mem1 = protect.Allocate(100);
        IntPtr ptr1;

        using (mem1.Acquire())
        {
            ptr1 = mem1.Pointer;
        }

        mem1.Dispose();

        // Act
        var mem2 = protect.Allocate(100);

        // Assert
        using (mem2.Acquire())
        {
            var ptr2 = mem2.Pointer;
            Assert.That(ptr2, Is.EqualTo(ptr1));
        }

        // Cleanup
        mem2.Dispose();
    }

    [Test]
    public void Free_TwoAdjacentRegions_ShouldMerge()
    {
        // Arrange
        using var protect = new ProtectMemory(300);

        var mem1 = protect.Allocate(100);
        var mem2 = protect.Allocate(100);

        mem1.Dispose();
        mem2.Dispose();

        // Act
        var mem3 = protect.Allocate(200);

        // Assert
        Assert.That(mem3.Length, Is.EqualTo(200));

        // Cleanup
        mem3.Dispose();
    }

    [Test]
    public void Allocate_ShouldTriggerCompact_WhenFragmented()
    {
        // Arrange
        using var protect = new ProtectMemory(300);

        var first = protect.Allocate(100);
        var middle = protect.Allocate(100);
        var last = protect.Allocate(100);

        first.Dispose();
        last.Dispose();

        // Act
        var large = protect.Allocate(150);

        // Assert
        Assert.That(large.Length, Is.EqualTo(150));

        // Cleanup
        large.Dispose();
        middle.Dispose();
    }

    [Test]
    public void Free_FirstThenSecond_ShouldMergeInto200()
    {
        // Arrange
        using var protect = new ProtectMemory(300);

        var first = protect.Allocate(100);
        var second = protect.Allocate(100);
        var third = protect.Allocate(100);

        first.Dispose();
        second.Dispose();

        // Act
        var merged = protect.Allocate(200);

        // Assert
        Assert.That(merged.Length, Is.EqualTo(200));

        // Cleanup
        merged.Dispose();
        third.Dispose();
    }

    [Test]
    public void Free_SecondThenFirst_ShouldMergeInto200()
    {
        // Arrange
        using var protect = new ProtectMemory(300);

        var first = protect.Allocate(100);
        var second = protect.Allocate(100);
        var third = protect.Allocate(100);

        second.Dispose();
        first.Dispose();

        // Act
        var merged = protect.Allocate(200);

        // Assert
        Assert.That(merged.Length, Is.EqualTo(200));

        merged.Dispose();
        third.Dispose();
    }

    [Test]
    public void Free_FirstThenThirdThenSecond_ShouldMergeAllInto300()
    {
        // Arrange
        using var protect = new ProtectMemory(300);

        var first = protect.Allocate(100);
        var second = protect.Allocate(100);
        var third = protect.Allocate(100);

        first.Dispose();
        third.Dispose();
        second.Dispose();

        // Act
        var merged = protect.Allocate(300);

        // Assert
        Assert.That(merged.Length, Is.EqualTo(300));

        // Cleanup
        merged.Dispose();
    }

    [Test]
    public unsafe void Compact_ShouldPreserveData_AndUpdatePointer()
    {
        // Arrange
        using var protect = new ProtectMemory(300);

        var first = protect.Allocate(100);
        var middle = protect.Allocate(100);
        var last = protect.Allocate(100);

        // We enter a unique pattern into the middle
        using (middle.Acquire())
        {
            var span = middle.AsSpan();

            for (var i = 0; i < span.Length; i++)
            {
                span[i] = (byte)(i % 251);
            }
        }

        // We will keep the old pointer to verify it changes after Compact
        IntPtr oldPtr;

        using (middle.Acquire())
        {
            oldPtr = middle.Pointer;
        }

        // Dismissing the first and last causes fragmentation
        first.Dispose();
        last.Dispose();

        // Act
        // This allocation will force Compact (because there is no continuous 150).
        var trigger = protect.Allocate(150);

        // Assert
        // We get the new Pointer 
        IntPtr newPtr;

        using (middle.Acquire())
        {
            newPtr = middle.Pointer;
        }

        Assert.That(newPtr, Is.Not.EqualTo(oldPtr),
            "Pointer should change after Compact relocation.");

        // We check whether the data is still correct
        using (middle.Acquire())
        {
            var span = middle.AsSpan();

            for (var i = 0; i < span.Length; i++)
            {
                Assert.That(span[i], Is.EqualTo((byte)(i % 251)),
                    $"Data corruption at index {i}");
            }
        }

        // Cleanup
        trigger.Dispose();
        middle.Dispose();
    }

    [Test]
    public unsafe void Compact_ShouldRelocateMiddleBlock_UsingSpanCopyTo_AndPreserveData()
    {
        // Arrange
        using var protect = new ProtectMemory(300);

        var first = protect.Allocate(50);
        var second = protect.Allocate(100);
        var third = protect.Allocate(150);

        // deterministyczny wzorzec dla drugiego bufora
        using (second.Acquire())
        {
            var span = second.AsSpan();

            for (var i = 0; i < span.Length; i++)
            {
                span[i] = (byte)((i * 7 + 13) % 256);
            }
        }

        // zapisujemy stary pointer
        IntPtr oldPtr;

        using (second.Acquire())
        {
            oldPtr = second.Pointer;
        }

        // powodujemy fragmentację
        first.Dispose();
        third.Dispose();

        // Act
        // brak ciągłego 200 → musi zajść Compact
        var large = protect.Allocate(200);

        // Assert
        IntPtr newPtr;

        using (second.Acquire())
        {
            newPtr = second.Pointer;
        }

        Assert.That(newPtr, Is.Not.EqualTo(oldPtr),
            "Pointer should change after Compact relocation.");

        // sprawdzamy czy dane nadal poprawne
        using (second.Acquire())
        {
            var span = second.AsSpan();

            for (var i = 0; i < span.Length; i++)
            {
                var expected = (byte)((i * 7 + 13) % 256);

                Assert.That(span[i], Is.EqualTo(expected),
                    $"Data corruption at index {i}");
            }
        }

        // Cleanup
        large.Dispose();
        second.Dispose();
    }

    [Test]
    public unsafe void Compact_ShouldRelocateMiddleBlock_Buffer_MemoryCopy_AndPreserveData()
    {
        // Arrange
        using var protect = new ProtectMemory(300);

        var first = protect.Allocate(150);
        var second = protect.Allocate(100);
        var third = protect.Allocate(50);

        // deterministyczny wzorzec dla drugiego bufora
        using (second.Acquire())
        {
            var span = second.AsSpan();

            for (var i = 0; i < span.Length; i++)
            {
                span[i] = (byte)((i * 7 + 13) % 256);
            }
        }

        // zapisujemy stary pointer
        IntPtr oldPtr;

        using (second.Acquire())
        {
            oldPtr = second.Pointer;
        }

        // powodujemy fragmentację
        first.Dispose();
        third.Dispose();

        // Act
        // brak ciągłego 200 → musi zajść Compact
        var large = protect.Allocate(200);

        // Assert
        IntPtr newPtr;

        using (second.Acquire())
        {
            newPtr = second.Pointer;
        }

        Assert.That(newPtr, Is.Not.EqualTo(oldPtr),
            "Pointer should change after Compact relocation.");

        // sprawdzamy czy dane nadal poprawne
        using (second.Acquire())
        {
            var span = second.AsSpan();

            for (var i = 0; i < span.Length; i++)
            {
                var expected = (byte)((i * 7 + 13) % 256);

                Assert.That(span[i], Is.EqualTo(expected),
                    $"Data corruption at index {i}");
            }
        }

        // Cleanup
        large.Dispose();
        second.Dispose();
    }
}

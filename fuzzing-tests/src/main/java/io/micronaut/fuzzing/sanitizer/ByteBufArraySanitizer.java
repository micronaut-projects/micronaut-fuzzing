package io.micronaut.fuzzing.sanitizer;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import com.code_intelligence.jazzer.api.Jazzer;
import io.netty.buffer.ByteBuf;

import java.lang.ref.SoftReference;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

final class ByteBufArraySanitizer {
    private static final AtomicInteger next = new AtomicInteger();
    private static final Slot[] slots = new Slot[256];

    private static final byte PATTERN_B1 = (byte) 0xd1;

    static {
        for (int i = 0; i < slots.length; i++) {
            slots[i] = new Slot();
        }
    }

    static byte baload(byte[] array, int index) {
        if (array[0] == PATTERN_B1) {
            array = checkIndexSlow(array, index);
        }
        return array[index];
    }

    static void bastore(byte[] array, int index, byte value) {
        if (array[0] == PATTERN_B1) {
            array = checkIndexSlow(array, index);
        }
        array[index] = value;
    }

    private static byte[] checkIndexSlow(byte[] array, int index) {
        Slot slot = findSlot(array);
        if (slot != null) {
            if (index < slot.start || index >= slot.end) {
                Jazzer.reportFindingFromHook(new FuzzerSecurityIssueCritical("Out-of-bounds array access"));
            }
            return slot.backing;
        } else {
            return array;
        }
    }

    private static Slot findSlot(byte[] guard) {
        if (guard[0] != PATTERN_B1 || guard.length < 2) {
            return null;
        }
        Slot slot = slots[guard[1] & 0xff];
        if (slot.guard.get() != guard) {
            return null;
        }
        return slot;
    }

    static byte[] byteBufArray(ByteBuf buf) {
        byte[] array = buf.array();
        int capacity = buf.capacity();
        if (capacity == array.length) {
            return array;
        }
        int offset = buf.arrayOffset();

        Slot existing = findSlot(array);
        if (existing != null) {
            if (existing.start == offset && existing.end == offset + capacity) {
                return array;
            }
            throw new UnsupportedOperationException("Nested .array?");
        }

        byte[] guard = new byte[array.length];
        guard[0] = PATTERN_B1;

        int i = next.getAndIncrement();
        guard[1] = (byte) i;

        Slot slot = slots[i % slots.length];
        slot.backing = array;
        slot.guard = new SoftReference<>(guard);
        slot.start = offset;
        slot.end = offset + capacity;

        return guard;
    }

    static byte[] arraysCopyOf(byte[] array, int newLength) {
        if (array.length > 0 && array[0] == PATTERN_B1) {
            array = checkRangeSlow(array, 0, newLength);
        }
        return Arrays.copyOf(array, newLength);
    }

    static byte[] arraysCopyOfRange(byte[] array, int from, int to) {
        if (array.length > 0 && array[0] == PATTERN_B1) {
            array = checkRangeSlow(array, from, to - from);
        }
        return Arrays.copyOfRange(array, from, to);
    }

    static void systemArraycopy(Object src, int srcPos, Object dest, int destPos, int length) {
        if (length != 0) {
            if (src instanceof byte[] s && s[0] == PATTERN_B1) {
                src = checkRangeSlow(s, srcPos, length);
            }
            if (dest instanceof byte[] d && d[0] == PATTERN_B1) {
                dest = checkRangeSlow(d, destPos, length);
            }
        }
        System.arraycopy(src, srcPos, dest, destPos, length);
    }

    private static byte[] checkRangeSlow(byte[] array, int pos, int len) {
        if (len <= 0) {
            return array;
        }
        Slot slot = findSlot(array);
        if (slot != null) {
            int start = slot.start;
            int end = slot.end;
            // Validate [pos, pos+len) within [start, end)
            long hi = (long) pos + (long) len; // avoid overflow surprises
            if (pos < start || hi > end) {
                Jazzer.reportFindingFromHook(new FuzzerSecurityIssueCritical("Out-of-bounds array access"));
            }
            return slot.backing;
        } else {
            return array;
        }
    }

    private static class Slot {
        byte[] backing;
        int start;
        int end;

        SoftReference<byte[]> guard;
    }
}

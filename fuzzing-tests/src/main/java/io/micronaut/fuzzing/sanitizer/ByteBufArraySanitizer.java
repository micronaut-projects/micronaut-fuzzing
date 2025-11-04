package io.micronaut.fuzzing.sanitizer;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import com.code_intelligence.jazzer.api.Jazzer;
import io.netty.buffer.ByteBuf;

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
            checkIndexSlow(array, index);
        }
        return array[index];
    }

    static void bastore(byte[] array, int index, byte value) {
        if (array[0] == PATTERN_B1) {
            checkIndexSlow(array, index);
        }
        array[index] = value;
    }

    private static void checkIndexSlow(byte[] array, int index) {
        Slot slot = findSlot(array);
        if (slot != null && (index < slot.start || index >= slot.end)) {
            Jazzer.reportFindingFromHook(new FuzzerSecurityIssueCritical("Out-of-bounds array access"));
        }
    }

    private static Slot findSlot(byte[] guard) {
        if (guard[0] != PATTERN_B1 || guard.length < 2) {
            return null;
        }
        Slot slot = slots[guard[1] & 0xff];
        if (slot.guard != guard) {
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
        slot.guard = guard;
        slot.start = offset;
        slot.end = offset + capacity;

        return guard;
    }

    private static class Slot {
        byte[] backing;
        int start;
        int end;

        byte[] guard;
    }
}

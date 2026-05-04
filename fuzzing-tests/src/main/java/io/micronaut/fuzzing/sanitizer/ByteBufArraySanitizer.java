/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.fuzzing.sanitizer;

import io.micronaut.core.annotation.Internal;
import io.netty.buffer.ByteBuf;

import java.lang.ref.SoftReference;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Tracks guarded byte arrays and reports out-of-bounds access detected through rewritten bytecode.
 */
@Internal
public final class ByteBufArraySanitizer {
    private static final AtomicInteger NEXT = new AtomicInteger();
    private static final Slot[] SLOTS = new Slot[256];

    private static final byte PATTERN_B1 = (byte) 0xd1;

    static {
        for (int i = 0; i < SLOTS.length; i++) {
            SLOTS[i] = new Slot();
        }
    }

    public static byte baload(byte[] array, int index) {
        if (array[0] == PATTERN_B1) {
            array = checkIndexSlow(array, index);
        }
        return array[index];
    }

    public static void bastore(byte[] array, int index, byte value) {
        if (array[0] == PATTERN_B1) {
            array = checkIndexSlow(array, index);
        }
        array[index] = value;
    }

    private static byte[] checkIndexSlow(byte[] array, int index) {
        Slot slot = findSlot(array);
        if (slot != null) {
            if (index < slot.start || index >= slot.end) {
                FindingReporter.reportCritical("Out-of-bounds array access");
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
        Slot slot = SLOTS[guard[1] & 0xff];
        SoftReference<byte[]> ref = slot.guard;
        if (ref == null || ref.get() != guard) {
            return null;
        }
        return slot;
    }

    public static byte[] byteBufArray(ByteBuf buf) {
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

        int i = NEXT.getAndIncrement();
        guard[1] = (byte) i;

        Slot slot = SLOTS[i % SLOTS.length];
        slot.backing = array;
        slot.guard = new SoftReference<>(guard);
        slot.start = offset;
        slot.end = offset + capacity;

        return guard;
    }

    public static byte[] arraysCopyOf(byte[] array, int newLength) {
        if (array.length > 0 && array[0] == PATTERN_B1) {
            array = checkRangeSlow(array, 0, newLength);
        }
        return Arrays.copyOf(array, newLength);
    }

    public static byte[] arraysCopyOfRange(byte[] array, int from, int to) {
        if (array.length > 0 && array[0] == PATTERN_B1) {
            array = checkRangeSlow(array, from, to - from);
        }
        return Arrays.copyOfRange(array, from, to);
    }

    public static void systemArraycopy(Object src, int srcPos, Object dest, int destPos, int length) {
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
            long hi = (long) pos + (long) len;
            if (pos < start || hi > end) {
                FindingReporter.reportCritical("Out-of-bounds array access");
            }
            return slot.backing;
        } else {
            return array;
        }
    }

    private static final class Slot {
        byte[] backing;
        int start;
        int end;

        SoftReference<byte[]> guard;
    }
}

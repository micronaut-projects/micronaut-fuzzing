package io.micronaut.fuzzing.sanitizer;

import io.netty.buffer.ByteBuf;

import java.util.Arrays;

final class SanitizerTransformerAccessors {
    private static volatile int sink;

    private SanitizerTransformerAccessors() {
    }

    static void aload(ByteBuf buffer) {
        if (buffer.arrayOffset() == 0) {
            sink = buffer.array()[16];
        } else {
            sink = buffer.array()[0];
        }
    }

    static void arraysCopyOf(ByteBuf buffer) {
        // pos == 0, start > 0 => violation
        Arrays.copyOf(buffer.array(), 1);
    }

    static void arraysCopyOfRange(ByteBuf buffer) {
        // [from,to) = [0,1) with start > 0 => violation
        Arrays.copyOfRange(buffer.array(), 0, 1);
    }

    static void systemArraycopySource(ByteBuf buffer, byte[] dest) {
        // srcPos == 0 with start > 0 => violation on source
        System.arraycopy(buffer.array(), 0, dest, 0, 1);
    }

    static void systemArraycopyDestination(byte[] src, ByteBuf buffer) {
        // destPos == 0 with start > 0 => violation on destination
        System.arraycopy(src, 0, buffer.array(), 0, 1);
    }
}

package io.micronaut.fuzzing.sanitizer;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;

@FuzzTarget(enableImplicitly = false)
public class TestOutOfBoundsTarget {
    static {
        SanitizerTransformer.installLocally();
    }

    private static volatile byte sink;

    public static void fuzzerTestOneInput(FuzzedDataProvider provider) {
        ByteBuf buffer = ByteBufAllocator.DEFAULT.heapBuffer(16);
        try {
            byte[] array = buffer.array();
            int ix = buffer.arrayOffset() + (provider.consumeByte() & 0xff);
            sink = array[Math.min(ix, array.length - 1)];
        } finally {
            buffer.release();
        }
    }

    static void main() {
        LocalJazzerRunner.create(TestOutOfBoundsTarget.class).fuzz();
    }
}

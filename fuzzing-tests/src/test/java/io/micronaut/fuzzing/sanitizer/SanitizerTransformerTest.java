package io.micronaut.fuzzing.sanitizer;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class SanitizerTransformerTest {
    @BeforeAll
    static void init() {
        SanitizerTransformer.installLocally();
    }

    private static volatile int sink;

    @Test
    public void aload() {
        ByteBuf buffer = ByteBufAllocator.DEFAULT.heapBuffer(16);
        try {
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> {
                if (buffer.arrayOffset() == 0) {
                    sink = buffer.array()[16];
                } else {
                    sink = buffer.array()[0];
                }
            });
        } finally {
            buffer.release();
        }
    }
}

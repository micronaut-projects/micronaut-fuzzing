package io.micronaut.fuzzing.sanitizer;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.codec.http.HttpRequestDecoder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

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

    @Test
    public void arraysCopyOf_oob() {
        ByteBuf parent = ByteBufAllocator.DEFAULT.heapBuffer(32);
        ByteBuf buffer = parent.retainedSlice(8, 16); // ensure non-zero arrayOffset -> guard path
        try {
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> {
                // pos == 0, start > 0 => violation
                Arrays.copyOf(buffer.array(), 1);
            });
        } finally {
            buffer.release();
            parent.release();
        }
    }

    @Test
    public void arraysCopyOfRange_oob() {
        ByteBuf parent = ByteBufAllocator.DEFAULT.heapBuffer(32);
        ByteBuf buffer = parent.retainedSlice(8, 16); // ensure non-zero arrayOffset -> guard path
        try {
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> {
                // [from,to) = [0,1) with start > 0 => violation
                Arrays.copyOfRange(buffer.array(), 0, 1);
            });
        } finally {
            buffer.release();
            parent.release();
        }
    }

    @Test
    public void systemArraycopy_oob_source() {
        ByteBuf parent = ByteBufAllocator.DEFAULT.heapBuffer(32);
        ByteBuf buffer = parent.retainedSlice(8, 16); // ensure non-zero arrayOffset -> guard path
        byte[] dest = new byte[1];
        try {
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> {
                // srcPos == 0 with start > 0 => violation on source
                System.arraycopy(buffer.array(), 0, dest, 0, 1);
            });
        } finally {
            buffer.release();
            parent.release();
        }
    }

    @Test
    public void systemArraycopy_oob_dest() {
        ByteBuf parent = ByteBufAllocator.DEFAULT.heapBuffer(32);
        ByteBuf buffer = parent.retainedSlice(8, 16); // ensure non-zero arrayOffset -> guard path
        byte[] src = new byte[1];
        try {
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> {
                // destPos == 0 with start > 0 => violation on destination
                System.arraycopy(src, 0, buffer.array(), 0, 1);
            });
        } finally {
            buffer.release();
            parent.release();
        }
    }

    @Test
    public void httpObjectDecoderInitializes() {
        new HttpRequestDecoder();
    }
}

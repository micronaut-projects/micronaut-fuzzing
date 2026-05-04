package io.micronaut.fuzzing.sanitizer;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.codec.http.HttpRequestDecoder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SanitizerTransformerTest {
    @BeforeAll
    static void init() {
        SanitizerTransformer.installLocally();
    }

    @Test
    public void loadsAreAccurate() {
        ByteBuf buffer = ByteBufAllocator.DEFAULT.heapBuffer(16);
        try {
            buffer.writeByte(1);
            buffer.writeByte(2);
            buffer.writeByte(3);

            byte[] array = buffer.array();
            assertEquals(1, array[0]);
            assertEquals(2, array[1]);
            assertEquals(3, array[2]);
            array[0] = 4;
            assertEquals(4, array[0]);

            byte[] tmp = new byte[3];
            System.arraycopy(array, 0, tmp, 0, 3);
            assertEquals(4, tmp[0]);
            assertEquals(2, tmp[1]);
            assertEquals(3, tmp[2]);

            tmp = Arrays.copyOf(array, 3);
            assertEquals(4, tmp[0]);
            assertEquals(2, tmp[1]);
            assertEquals(3, tmp[2]);

            tmp = Arrays.copyOfRange(array, 1, 3);
            assertEquals(2, tmp[0]);
            assertEquals(3, tmp[1]);
        } finally {
            buffer.release();
        }
    }

    @Test
    public void aload() throws ReflectiveOperationException {
        ByteBuf buffer = ByteBufAllocator.DEFAULT.heapBuffer(16);
        try {
            assertFinding("aload", new Class<?>[] {ByteBuf.class}, buffer);
        } finally {
            buffer.release();
        }
    }

    @Test
    public void arraysCopyOf_oob() throws ReflectiveOperationException {
        ByteBuf parent = ByteBufAllocator.DEFAULT.heapBuffer(32);
        ByteBuf buffer = parent.retainedSlice(8, 16); // ensure non-zero arrayOffset -> guard path
        try {
            assertFinding("arraysCopyOf", new Class<?>[] {ByteBuf.class}, buffer);
        } finally {
            buffer.release();
            parent.release();
        }
    }

    @Test
    public void arraysCopyOfRange_oob() throws ReflectiveOperationException {
        ByteBuf parent = ByteBufAllocator.DEFAULT.heapBuffer(32);
        ByteBuf buffer = parent.retainedSlice(8, 16); // ensure non-zero arrayOffset -> guard path
        try {
            assertFinding("arraysCopyOfRange", new Class<?>[] {ByteBuf.class}, buffer);
        } finally {
            buffer.release();
            parent.release();
        }
    }

    @Test
    public void systemArraycopy_oob_source() throws ReflectiveOperationException {
        ByteBuf parent = ByteBufAllocator.DEFAULT.heapBuffer(32);
        ByteBuf buffer = parent.retainedSlice(8, 16); // ensure non-zero arrayOffset -> guard path
        byte[] dest = new byte[1];
        try {
            assertFinding("systemArraycopySource", new Class<?>[] {ByteBuf.class, byte[].class}, buffer, dest);
        } finally {
            buffer.release();
            parent.release();
        }
    }

    @Test
    public void systemArraycopy_oob_dest() throws ReflectiveOperationException {
        ByteBuf parent = ByteBufAllocator.DEFAULT.heapBuffer(32);
        ByteBuf buffer = parent.retainedSlice(8, 16); // ensure non-zero arrayOffset -> guard path
        byte[] src = new byte[1];
        try {
            assertFinding("systemArraycopyDestination", new Class<?>[] {byte[].class, ByteBuf.class}, src, buffer);
        } finally {
            buffer.release();
            parent.release();
        }
    }

    private static void assertFinding(String methodName, Class<?>[] parameterTypes, Object... arguments) throws ReflectiveOperationException {
        Method method = Class.forName("io.micronaut.fuzzing.sanitizer.SanitizerTransformerAccessors")
            .getDeclaredMethod(methodName, parameterTypes);
        method.setAccessible(true);
        InvocationTargetException exception = Assertions.assertThrows(InvocationTargetException.class, () -> method.invoke(null, arguments));
        Assertions.assertInstanceOf(FuzzerSecurityIssueCritical.class, exception.getCause());
    }

    @Test
    public void httpObjectDecoderInitializes() {
        new HttpRequestDecoder();
    }

}

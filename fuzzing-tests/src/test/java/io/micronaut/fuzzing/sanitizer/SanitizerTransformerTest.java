package io.micronaut.fuzzing.sanitizer;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import com.github.luben.zstd.Zstd;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.HttpRequestDecoder;
import net.jpountz.xxhash.StreamingXXHash64;
import net.jpountz.xxhash.XXHashFactory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.zip.CRC32;
import java.util.zip.Checksum;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SanitizerTransformerTest {
    @BeforeAll
    static void init() {
        SanitizerTransformer.installLocally();
    }

    private static volatile int sink;

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
    public void zipUsesBackingArray() throws Exception {
        byte[] plain = "hello hello hello world".getBytes(StandardCharsets.UTF_8);
        Deflater deflater = new Deflater();
        Inflater inflater = new Inflater();
        ByteBuf parent = ByteBufAllocator.DEFAULT.heapBuffer(256);
        ByteBuf compressed = parent.retainedSlice(8, 64); // ensure non-zero arrayOffset -> guard path
        ByteBuf decompressed = parent.retainedSlice(100, 64);
        try {
            deflater.setInput(plain);
            deflater.finish();
            int n = deflater.deflate(compressed.array(), compressed.arrayOffset(), compressed.capacity());
            compressed.writerIndex(n);

            inflater.setInput(compressed.array(), compressed.arrayOffset(), n);
            int m = inflater.inflate(decompressed.array(), decompressed.arrayOffset(), decompressed.capacity());
            decompressed.writerIndex(m);
            assertEquals(new String(plain, StandardCharsets.UTF_8), decompressed.toString(StandardCharsets.UTF_8));

            Checksum crc = new CRC32();
            crc.update(decompressed.array(), decompressed.arrayOffset(), m);
            CRC32 expected = new CRC32();
            expected.update(plain);
            assertEquals(expected.getValue(), crc.getValue());

            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () ->
                inflater.inflate(decompressed.array(), decompressed.arrayOffset(), decompressed.capacity() + 1));
        } finally {
            deflater.end();
            inflater.end();
            compressed.release();
            decompressed.release();
            parent.release();
        }
    }

    @Test
    public void httpObjectDecoderInitializes() {
        new HttpRequestDecoder();
    }

    private static final byte[] HELLO = "hello world".getBytes(StandardCharsets.UTF_8);

    /**
     * Run a test with a pooled heap buffer that contains {@link #HELLO} and has a guard array.
     */
    private static void withGuardedHello(GuardedTest test) throws Exception {
        ByteBuf parent = ByteBufAllocator.DEFAULT.heapBuffer(64);
        ByteBuf buffer = parent.retainedSlice(8, 32); // ensure non-zero arrayOffset -> guard path
        try {
            buffer.clear().writeBytes(HELLO);
            test.run(buffer, buffer.array(), buffer.arrayOffset());
        } finally {
            buffer.release();
            parent.release();
        }
    }

    @Test
    public void byteBufMethodsUseBackingArray() throws Exception {
        withGuardedHello((buffer, array, offset) -> {
            ByteBuf target = ByteBufAllocator.DEFAULT.heapBuffer(64);
            try {
                // like PieceAccumulator
                target.writeBytes(array, offset, HELLO.length);
                assertEquals("hello world", target.toString(StandardCharsets.UTF_8));

                // writes reach the backing array
                target.getBytes(0, array, offset + 6, 5);
                target.setBytes(0, "HELLO".getBytes(StandardCharsets.UTF_8));
                target.getBytes(0, array, offset, 5);
                assertEquals("HELLO hello", buffer.toString(StandardCharsets.UTF_8));

                Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> target.writeBytes(array, offset - 1, 2));
                Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> target.getBytes(0, array, offset + 31, 2));
                // whole array
                Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> target.setBytes(0, array));
            } finally {
                target.release();
            }
        });
    }

    @Test
    public void unpooledWrappedBufferKeepsBounds() throws Exception {
        withGuardedHello((buffer, array, offset) -> {
            // like Base64.encode
            ByteBuf wrapped = Unpooled.wrappedBuffer(array, offset, buffer.capacity());
            assertEquals("hello world", wrapped.toString(0, HELLO.length, StandardCharsets.UTF_8));
            wrapped.setByte(0, 'j');
            assertEquals("jello world", buffer.toString(StandardCharsets.UTF_8));
            // the wrapped buffer has a guard array with the same bounds
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> sink = wrapped.array()[wrapped.arrayOffset() + buffer.capacity()]);
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> Unpooled.wrappedBuffer(array, offset, buffer.capacity() + 1));
        });
    }

    @Test
    public void jdkMethodsUseBackingArray() throws Exception {
        withGuardedHello((buffer, array, offset) -> {
            assertEquals("hello world", new String(array, offset, HELLO.length, StandardCharsets.UTF_8));
            //noinspection deprecation
            assertEquals("hello world", new String(array, 0, offset, HELLO.length));
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> new String(array, offset - 1, 1, StandardCharsets.UTF_8));
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> new String(array, StandardCharsets.UTF_8));

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(array, offset, HELLO.length);
            Assertions.assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(HELLO), digest.digest());

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(array, offset, HELLO.length);
            Assertions.assertArrayEquals(HELLO, baos.toByteArray());
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> baos.write(array, offset + 30, 3));

            // inherited from FilterOutputStream
            baos.reset();
            OutputStream filter = new InheritingOutputStream(baos);
            filter.write(array, offset, HELLO.length);
            Assertions.assertArrayEquals(HELLO, baos.toByteArray());

            new ByteArrayInputStream(HELLO).read(array, offset + 20, 5);
            assertEquals("hello", buffer.toString(20, 5, StandardCharsets.UTF_8));

            Assertions.assertTrue(Arrays.equals(array, offset, offset + HELLO.length, HELLO, 0, HELLO.length));
            Arrays.fill(array, offset, offset + 5, (byte) 'x');
            assertEquals("xxxxx world", buffer.toString(0, HELLO.length, StandardCharsets.UTF_8));
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> Arrays.fill(array, offset + 30, offset + 33, (byte) 'x'));
        });
    }

    @Test
    public void instrumentedOverrideSeesGuardArray() throws Exception {
        withGuardedHello((buffer, array, offset) -> {
            InstrumentedOutputStream stream = new InstrumentedOutputStream();
            OutputStream asStream = stream;
            asStream.write(array, offset, HELLO.length);
            Assertions.assertSame(array, stream.received);
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> sink = stream.received[offset - 1]);
        });
    }

    @Test
    public void byteBufferWrap() throws Exception {
        withGuardedHello((buffer, array, offset) -> {
            ByteBuffer nio = ByteBuffer.wrap(array, offset, HELLO.length);
            assertEquals("hello world", StandardCharsets.UTF_8.decode(nio).toString());
            // like JacksonDatabindMapper
            byte[] fromNio = nio.array();
            Assertions.assertSame(array, fromNio);
            assertEquals('h', fromNio[offset]);
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> sink = fromNio[offset - 1]);
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> ByteBuffer.wrap(array, offset + 30, 3));
        });
    }

    @Test
    public void nativeMethodsUseBackingArray() throws Exception {
        withGuardedHello((buffer, array, offset) -> {
            XXHashFactory fastest = XXHashFactory.fastestInstance();
            int expected = XXHashFactory.safeInstance().hash32().hash(HELLO, 0, HELLO.length, 0x9747b28c);
            assertEquals(expected, fastest.hash32().hash(array, offset, HELLO.length, 0x9747b28c), fastest.toString());
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> fastest.hash32().hash(array, offset - 1, HELLO.length, 0));

            // zstd-jni uses JNI before Java 22, and MemorySegment.ofArray after
            byte[] frame = Zstd.compress(HELLO);
            buffer.clear().writeBytes(frame);
            assertEquals(HELLO.length, Zstd.getFrameContentSize(array, offset, frame.length));
        });
    }

    @Test
    public void platformModuleUsesBackingArray() throws Exception {
        withGuardedHello((buffer, array, offset) -> {
            // javax.crypto is in the java.base module, but not in a "java." package
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(HELLO, "HmacSHA256"));
            mac.update(array, offset, HELLO.length);
            byte[] actual = mac.doFinal();
            Assertions.assertArrayEquals(mac.doFinal(HELLO), actual);
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> mac.update(array, offset - 1, 1));
        });
    }

    @Test
    public void superCallUsesBackingArray() throws Exception {
        withGuardedHello((buffer, array, offset) -> {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            SuperCallingOutputStream stream = new SuperCallingOutputStream(baos);
            stream.write(array, offset, HELLO.length);
            Assertions.assertSame(array, stream.received);
            Assertions.assertArrayEquals(HELLO, baos.toByteArray());
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> stream.write(array, offset - 1, 2));
        });
    }

    @Test
    public void interfaceDispatchToInstrumentedImplementation() throws Exception {
        withGuardedHello((buffer, array, offset) -> {
            RecordingChecksum recording = new RecordingChecksum();
            Checksum checksum = recording;
            checksum.update(array, offset, HELLO.length);
            Assertions.assertSame(array, recording.received);
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> sink = recording.received[offset - 1]);

            Checksum crc = new CRC32();
            crc.update(array, offset, HELLO.length);
            CRC32 expected = new CRC32();
            expected.update(HELLO);
            assertEquals(expected.getValue(), crc.getValue());
        });
    }

    @Test
    public void nestedAndBranchingConstructorCalls() throws Exception {
        withGuardedHello((buffer, array, offset) -> {
            boolean guarded = buffer.capacity() > 0;
            // branches between NEW and the constructor call
            String s = new String(guarded ? array : HELLO, guarded ? offset : 0, HELLO.length, guarded ? StandardCharsets.UTF_8 : StandardCharsets.US_ASCII);
            assertEquals("hello world", s);
            // NEW in the argument of another constructor
            ByteArrayInputStream in = new ByteArrayInputStream(new String(array, offset, HELLO.length, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8));
            Assertions.assertArrayEquals(HELLO, in.readAllBytes());
            // NEW in the argument of this(...)
            assertEquals("hello world", new StringHolder(array, offset).value);
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> new StringHolder(array, offset + 30));
        });
    }

    @Test
    public void staticCallWithLongParameters() throws Exception {
        withGuardedHello((buffer, array, offset) -> {
            XXHashFactory fastest = XXHashFactory.fastestInstance();
            XXHashFactory safe = XXHashFactory.safeInstance();
            // XXH64(byte[], int, int, long)
            assertEquals(safe.hash64().hash(HELLO, 0, HELLO.length, 42L), fastest.hash64().hash(array, offset, HELLO.length, 42L), fastest.toString());
            // XXH64_update(long, byte[], int, int)
            StreamingXXHash64 streaming = fastest.newStreamingHash64(42L);
            streaming.update(array, offset, HELLO.length);
            assertEquals(safe.hash64().hash(HELLO, 0, HELLO.length, 42L), streaming.getValue());
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> streaming.update(array, offset + 30, 3));
            streaming.close();
        });
    }

    @Test
    public void byteBufferWrapWholeArray() throws Exception {
        withGuardedHello((buffer, array, offset) -> {
            ByteBuffer nio = ByteBuffer.wrap(array);
            nio.position(offset).limit(offset + HELLO.length);
            assertEquals("hello world", StandardCharsets.UTF_8.decode(nio).toString());
            byte[] fromNio = nio.array();
            Assertions.assertSame(array, fromNio);
            Assertions.assertThrows(FuzzerSecurityIssueCritical.class, () -> sink = fromNio[offset + 32]);
        });
    }

    @FunctionalInterface
    private interface GuardedTest {
        void run(ByteBuf buffer, byte[] array, int offset) throws Exception;
    }

    private static final class InheritingOutputStream extends FilterOutputStream {
        InheritingOutputStream(OutputStream out) {
            super(out);
        }
    }

    private static final class SuperCallingOutputStream extends FilterOutputStream {
        byte[] received;

        SuperCallingOutputStream(OutputStream out) {
            super(out);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            received = b;
            super.write(b, off, len);
        }
    }

    private static final class RecordingChecksum implements Checksum {
        byte[] received;

        @Override
        public void update(int b) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void update(byte[] b, int off, int len) {
            received = b;
        }

        @Override
        public long getValue() {
            return 0;
        }

        @Override
        public void reset() {
        }
    }

    private static final class StringHolder {
        final String value;

        StringHolder(byte[] array, int offset) {
            this(new String(array, offset, HELLO.length, StandardCharsets.UTF_8));
        }

        StringHolder(String value) {
            this.value = value;
        }
    }

    private static final class InstrumentedOutputStream extends OutputStream {
        byte[] received;

        @Override
        public void write(int b) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void write(byte[] b, int off, int len) {
            received = b;
        }
    }
}

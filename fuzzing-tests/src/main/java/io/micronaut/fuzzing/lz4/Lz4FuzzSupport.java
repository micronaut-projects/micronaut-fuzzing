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
package io.micronaut.fuzzing.lz4;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.fuzzing.CpuBudget;
import net.jpountz.lz4.LZ4Compressor;
import net.jpountz.lz4.LZ4Exception;
import net.jpountz.lz4.LZ4Factory;
import net.jpountz.lz4.LZ4SafeDecompressor;
import net.jpountz.xxhash.XXHashFactory;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.function.IntFunction;

/**
 * Shared helpers for the lz4-java fuzz targets.
 *
 * <p>The targets do not use Netty or the sanitizer. They hand plain arrays and exactly sized
 * {@link ByteBuffer}s to lz4-java, so that an out-of-bounds access in the Java code fails with
 * an exception. The memory around the region that lz4-java may touch is filled with a pattern
 * and checked afterwards, which also detects stray writes by the native and {@code Unsafe} code.
 *
 * <p>lz4-java does not log, so the targets do not check {@code FlagAppender}.
 */
final class Lz4FuzzSupport {
    /**
     * Upper bound for any decompressed length that the targets allocate.
     */
    static final int MAX_DEST_LENGTH = 1 << 17;
    /**
     * The maximum ratio of decompressed to compressed length of an LZ4 block. Larger destinations
     * than this are not more interesting, but slow down the fuzzer.
     */
    static final int MAX_COMPRESSION_RATIO = 255;
    /**
     * Upper bound for the padding before and after the region passed to lz4-java.
     */
    static final int MAX_PADDING = 16;
    /**
     * Upper bound for the offset of a {@link ByteBuffer} slice in its parent buffer.
     */
    static final int MAX_SHIFT = 15;

    private static final int DIRECT_BUFFER_GRANULARITY = 1 << 12;
    private static final byte[] SRC_FILL = {0x00, (byte) 0xFF, 0x5A, (byte) 0xA5};
    private static final byte[] DEST_CANARY = {(byte) 0xCC, 0x33, (byte) 0x96, 0x69};

    private static final Codec JAVA_SAFE = new Codec(
        "java-safe", false, LZ4Factory.safeInstance(), XXHashFactory.safeInstance());
    @SuppressWarnings("deprecation")
    // unsafeInstance() returns the safe implementation in this lz4-java version. The insecure
    // factory is the only way to reach the Unsafe code. Only its safe decompressor and its
    // compressors are used, never its (documented insecure) fast decompressor.
    private static final Codec JAVA_UNSAFE = new Codec(
        "java-unsafe", false, LZ4Factory.unsafeInsecureInstance(), XXHashFactory.unsafeInstance());
    @Nullable
    private static final Codec NATIVE = loadNative();
    private static final List<Codec> ALL_CODECS = NATIVE == null
        ? List.of(JAVA_SAFE, JAVA_UNSAFE)
        : List.of(JAVA_SAFE, JAVA_UNSAFE, NATIVE);

    /**
     * Direct buffers are only freed by the GC, and allocating many of them triggers
     * {@code System.gc()} calls that distort the CPU time. They are reused instead: each input
     * takes buffers from this list in order (see {@link #resetDirectBuffers()}).
     */
    private static final List<ByteBuffer> DIRECT_BUFFERS = new ArrayList<>();
    private static int directBuffersUsed;

    private Lz4FuzzSupport() {
    }

    /**
     * @return All available implementations. The first one is the Java safe implementation,
     * which serves as the reference.
     */
    static List<Codec> codecs() {
        return ALL_CODECS;
    }

    /**
     * @return The Java implementations only, as if the native library could not be loaded
     */
    static List<Codec> javaCodecs() {
        return List.of(JAVA_SAFE, JAVA_UNSAFE);
    }

    /**
     * @return Whether the JNI implementation could be loaded on this machine
     */
    static boolean isNativeAvailable() {
        return NATIVE != null;
    }

    @Nullable
    private static Codec loadNative() {
        try {
            return new Codec("native", true, LZ4Factory.nativeInstance(), XXHashFactory.nativeInstance());
        } catch (LinkageError | RuntimeException | AssertionError e) {
            // LZ4Factory wraps loading failures in an AssertionError. Fuzz the Java code only.
            return null;
        }
    }

    static byte srcFill(int codecIndex) {
        return SRC_FILL[codecIndex % SRC_FILL.length];
    }

    static byte destCanary(int codecIndex) {
        return DEST_CANARY[codecIndex % DEST_CANARY.length];
    }

    static int readIntLE(byte[] data, int off) {
        return (data[off] & 0xFF) | (data[off + 1] & 0xFF) << 8 | (data[off + 2] & 0xFF) << 16 | data[off + 3] << 24;
    }

    /**
     * Runs one input with the same CPU budget as {@code EmbeddedChannelFuzzerBase}, see
     * {@link CpuBudget#runWithRetry}.
     *
     * @param inputLength  The input length
     * @param inputCpuTime The CPU budget per input byte, in {@link CpuBudget} units
     * @param action       The action to run
     */
    static void runWithCpuLimit(int inputLength, long inputCpuTime, Runnable action) {
        CpuBudget.runWithRetry(inputLength, CpuBudget.DEFAULT_BASE_CPU_TIME, inputCpuTime, action);
    }

    /**
     * Makes the cached direct buffers available again. Called at the start of each input, after
     * which no region of the previous input is used anymore.
     */
    static void resetDirectBuffers() {
        directBuffersUsed = 0;
    }

    private static ByteBuffer directBuffer(int size) {
        ByteBuffer buffer = directBuffersUsed < DIRECT_BUFFERS.size() ? DIRECT_BUFFERS.get(directBuffersUsed) : null;
        if (buffer == null || buffer.capacity() < size) {
            int capacity = (size + DIRECT_BUFFER_GRANULARITY - 1) / DIRECT_BUFFER_GRANULARITY * DIRECT_BUFFER_GRANULARITY;
            buffer = ByteBuffer.allocateDirect(capacity);
            if (directBuffersUsed < DIRECT_BUFFERS.size()) {
                DIRECT_BUFFERS.set(directBuffersUsed, buffer);
            } else {
                DIRECT_BUFFERS.add(buffer);
            }
        }
        directBuffersUsed++;
        return buffer.slice(0, size);
    }

    /**
     * Compares the outcome of an implementation with the reference outcome.
     *
     * @param subject   The implementation, for the failure message
     * @param operation The operation, for the failure message
     * @param reference The outcome of the reference implementation
     * @param other     The outcome of the implementation under test
     * @param lenient   If {@code true}, only compare the output if both succeed. This is used for
     *                  the native implementation. The LZ4 format requires a block to end with at
     *                  least 5 literals, and the last match to start at least 12 bytes before the
     *                  end. The C and the Java decoder enforce these rules differently (the C
     *                  decoder relative to {@code maxDestLen}, the Java decoder relative to the
     *                  end of the input), so each of them accepts some invalid blocks that the
     *                  other one rejects.
     */
    static void compare(Object subject, String operation, Outcome reference, Outcome other, boolean lenient) {
        if (lenient && !(reference.succeeded() && other.succeeded())) {
            return;
        }
        if (!reference.sameAs(other)) {
            throw new AssertionError(subject + " " + operation + ": reference " + reference + " but got " + other);
        }
    }

    /**
     * Checks a returned length. The message is only built on failure.
     *
     * @param subject   The implementation, for the failure message
     * @param operation The operation, for the failure message
     * @param length    The returned length
     * @param max       The maximum valid length
     */
    static void checkLength(Object subject, String operation, int length, int max) {
        if (length < 0 || length > max) {
            throw new AssertionError(subject + " " + operation + " returned length " + length + ", expected 0.." + max);
        }
    }

    static String hex(byte[] bytes) {
        if (bytes.length > 64) {
            return HexFormat.of().formatHex(bytes, 0, 64) + "...(" + bytes.length + " bytes)";
        }
        return HexFormat.of().formatHex(bytes);
    }

    /**
     * Kind of {@link ByteBuffer} that is passed to lz4-java.
     */
    enum BufferKind {
        HEAP, DIRECT, READ_ONLY_HEAP;

        static BufferKind fromBits(int bits, boolean allowReadOnly) {
            BufferKind[] values = values();
            return values[bits % (allowReadOnly ? values.length : values.length - 1)];
        }
    }

    /**
     * One implementation of lz4-java.
     *
     * @param name             Name for failure messages
     * @param nativeCode       Whether this is the JNI implementation
     * @param safeDecompressor The safe decompressor
     * @param fastCompressor   The fast compressor
     * @param highCompressor   The high compressor for a compression level
     * @param hashes           The xxhash implementation
     * @param factory          The factory, or {@code null} for test doubles
     */
    record Codec(
        String name,
        boolean nativeCode,
        LZ4SafeDecompressor safeDecompressor,
        LZ4Compressor fastCompressor,
        IntFunction<LZ4Compressor> highCompressor,
        XXHashFactory hashes,
        @Nullable LZ4Factory factory
    ) {
        Codec(String name, boolean nativeCode, LZ4Factory factory, XXHashFactory hashes) {
            this(name, nativeCode, factory.safeDecompressor(), factory.fastCompressor(), factory::highCompressor, hashes, factory);
        }

        /**
         * Replaces the safe decompressor, for tests that check that the oracles work.
         *
         * @param decompressor The decompressor
         * @return The modified codec
         */
        Codec withSafeDecompressor(LZ4SafeDecompressor decompressor) {
            return new Codec(name, nativeCode, decompressor, fastCompressor, highCompressor, hashes, null);
        }

        /**
         * Replaces the compressors, for tests that check that the oracles work.
         *
         * @param compressor The compressor
         * @return The modified codec
         */
        Codec withCompressor(LZ4Compressor compressor) {
            return new Codec(name, nativeCode, safeDecompressor, compressor, level -> compressor, hashes, null);
        }
    }

    /**
     * Result of a block operation: the output bytes, or a failure with {@link LZ4Exception}.
     */
    static final class Outcome {
        static final Outcome FAILURE = new Outcome(null);

        @Nullable
        private final byte[] output;

        private Outcome(@Nullable byte[] output) {
            this.output = output;
        }

        static Outcome success(byte[] output) {
            return new Outcome(output);
        }

        boolean succeeded() {
            return output != null;
        }

        byte[] output() {
            if (output == null) {
                throw new IllegalStateException("No output");
            }
            return output;
        }

        boolean sameAs(Outcome other) {
            return Arrays.equals(output, other.output);
        }

        @Override
        public String toString() {
            return output == null ? "LZ4Exception" : "success(" + hex(output) + ")";
        }
    }

    /**
     * A region of memory that is passed to lz4-java, either as an array or as a {@link ByteBuffer}
     * view of a larger parent buffer. The parent buffer is never passed to lz4-java, so that
     * writes outside of the view can be detected.
     */
    static final class Region {
        @Nullable
        private final byte[] array;
        @Nullable
        private final ByteBuffer view;
        private final ByteBuffer parent;
        private final int start;
        private final int size;

        private Region(@Nullable byte[] array, @Nullable ByteBuffer view, ByteBuffer parent, int start, int size) {
            this.array = array;
            this.view = view;
            this.parent = parent;
            this.start = start;
            this.size = size;
        }

        static Region array(int size, byte fill) {
            byte[] array = new byte[size];
            Arrays.fill(array, fill);
            return new Region(array, null, ByteBuffer.wrap(array), 0, size);
        }

        static Region buffer(BufferKind kind, int shift, int size, ByteOrder order, byte fill) {
            int parentSize = shift + size + MAX_SHIFT;
            ByteBuffer parent = kind == BufferKind.DIRECT ? directBuffer(parentSize) : ByteBuffer.allocate(parentSize);
            byte[] pattern = new byte[parentSize];
            Arrays.fill(pattern, fill);
            parent.put(0, pattern);
            ByteBuffer view = parent.slice(shift, size);
            if (kind == BufferKind.READ_ONLY_HEAP) {
                view = view.asReadOnlyBuffer();
            }
            view.order(order);
            return new Region(null, view, parent, shift, size);
        }

        /**
         * @return A region with the given content at {@code off}, of the same kind as this one
         */
        Region put(int off, byte[] data) {
            parent.put(start + off, data);
            return this;
        }

        byte[] array() {
            if (array == null) {
                throw new IllegalStateException("Not an array region");
            }
            return array;
        }

        ByteBuffer buffer() {
            if (view == null) {
                throw new IllegalStateException("Not a buffer region");
            }
            return view;
        }

        int size() {
            return size;
        }

        byte[] get(int off, int len) {
            byte[] result = new byte[len];
            parent.get(start + off, result);
            return result;
        }

        byte[] snapshot() {
            byte[] result = new byte[parent.capacity()];
            parent.get(0, result);
            return result;
        }

        /**
         * Checks that lz4-java did not modify the memory outside of {@code [from, to)} and did not
         * move the position or limit of the view.
         *
         * @param subject   The implementation, for the failure message
         * @param operation The operation, for the failure message
         * @param before The snapshot taken before the operation
         * @param from   Start of the region that may be modified, relative to the view
         * @param to     End of the region that may be modified, relative to the view
         */
        void checkUnchangedOutside(Object subject, String operation, byte[] before, int from, int to) {
            byte[] after = snapshot();
            int writableStart = from == to ? after.length : start + from;
            int writableEnd = from == to ? after.length : start + to;
            int changed = Arrays.mismatch(before, 0, writableStart, after, 0, writableStart);
            if (changed < 0) {
                changed = Arrays.mismatch(before, writableEnd, before.length, after, writableEnd, after.length);
                if (changed >= 0) {
                    changed += writableEnd;
                }
            }
            if (changed >= 0) {
                throw new AssertionError(subject + " " + operation + " modified memory outside of [" + from + ", " + to + ") at offset " + (changed - start));
            }
            if (view != null && (view.position() != 0 || view.limit() != size)) {
                throw new AssertionError(subject + " " + operation + " moved the buffer position or limit: " + view);
            }
        }

        void checkUnchanged(Object subject, String operation, byte[] before) {
            checkUnchangedOutside(subject, operation, before, 0, 0);
        }
    }
}

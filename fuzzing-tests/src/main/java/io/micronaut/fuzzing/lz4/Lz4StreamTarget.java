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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.DictResource;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.lz4.Lz4FuzzSupport.Codec;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import net.jpountz.lz4.LZ4BlockInputStream;
import net.jpountz.lz4.LZ4BlockOutputStream;
import net.jpountz.lz4.LZ4Compressor;
import net.jpountz.lz4.LZ4Exception;
import net.jpountz.lz4.LZ4FrameInputStream;
import net.jpountz.lz4.LZ4FrameOutputStream;
import net.jpountz.xxhash.StreamingXXHash32;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Fuzz target for the LZ4Block ({@link LZ4BlockInputStream}) and LZ4 frame
 * ({@link LZ4FrameInputStream}) stream formats.
 *
 * <p>Depending on the mode, the input is either decoded as a stream, or compressed with the
 * matching output stream and decoded again. Every implementation (Java safe, Java {@code Unsafe}
 * and JNI if it can be loaded) is used, always with an explicit safe decompressor. Oracles:
 * <ul>
 *     <li>Decoding fails only with an {@link IOException}. The streams wrap unexpected
 *     {@link RuntimeException}s in an {@link IOException}, so the cause chain may only contain
 *     {@link IOException}s and {@link LZ4Exception}s, or for the frame descriptor the exceptions
 *     that the descriptor validation throws on purpose. After a failure, the stream keeps failing.</li>
 *     <li>All implementations decode the same data and fail at the same point. The native and the
 *     Java implementations disagree about some invalid blocks, so for the native implementation
 *     the data is only compared up to the first failure.</li>
 *     <li>If a single frame declares its content size, the decoded size matches.</li>
 *     <li>Data compressed with any implementation, block size, flags and write/flush pattern
 *     decodes to the input with every implementation, also for concatenated streams.</li>
 * </ul>
 *
 * <p>To bound allocations, {@code acceptOversizedBlocks} is only used for inputs where every
 * reachable block header declares a compressed length of at most the input length.
 */
@FuzzTarget
@Dict({
    "LZ4Block", "LZ4Block\u0010", "LZ4Block ", "LZ4Block\u001a", "LZ4Block*", "LZ4Block/",
    "\u0004\"M\u0018", "P*M\u0018", "@@", "`@", "dp", "lP", "h`",
    "\u0000\u0000\u0000\u0000",
})
@DictResource("io/micronaut/fuzzing/lz4/lz4.dict")
public final class Lz4StreamTarget {
    static final int MODE_BLOCK_DECODE = 0;
    static final int MODE_FRAME_DECODE = 1;
    static final int MODE_BLOCK_ROUND_TRIP = 2;
    static final int MODE_FRAME_ROUND_TRIP = 3;

    static final int FLAG_STOP_ON_EMPTY_BLOCK = 1;
    static final int FLAG_ACCEPT_OVERSIZED_BLOCKS = 1 << 1;
    static final int FLAG_READ_SINGLE_FRAME = 1 << 2;
    static final int FLAG_QUERY_CONTENT_SIZE = 1 << 3;
    static final int FLAG_SKIP = 1 << 4;
    static final int FLAG_HIGH_COMPRESSION = 1 << 5;
    static final int FLAG_SYNC_FLUSH = 1 << 6;
    static final int FLAG_FLUSH = 1 << 7;
    static final int FLAG_FINISH = 1 << 8;
    static final int FLAG_CONCATENATE = 1 << 9;
    static final int FLAG_CONTENT_CHECKSUM = 1 << 10;
    static final int FLAG_BLOCK_CHECKSUM = 1 << 11;
    static final int FLAG_CONTENT_SIZE = 1 << 12;
    static final int FRAME_BLOCK_SIZE_SHIFT = 13;

    private static final long INPUT_CPU_TIME = 100;
    private static final int BLOCK_SEED = 0x9747b28c;
    private static final int BLOCK_MAGIC_LENGTH = 8;
    private static final int BLOCK_HEADER_LENGTH = BLOCK_MAGIC_LENGTH + 13;
    private static final byte[] BLOCK_MAGIC = {'L', 'Z', '4', 'B', 'l', 'o', 'c', 'k'};
    private static final int MIN_BLOCK_SIZE = 64;
    private static final int MAX_BLOCK_SIZE = 1 << 17;
    private static final int MAX_CHUNK_SIZE = 1 << 12;
    private static final int CHUNK_SIZES = 4;
    private static final int SKIP_INTERVAL = 3;
    private static final int MAX_OUTPUT = 1 << 22;
    private static final int MIN_FRAME_BLOCK_SIZE = 1 << 16;
    private static final String INVALID_DESCRIPTOR = "Invalid or unsupported frame descriptor";

    private Lz4StreamTarget() {
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider provider) {
        Config config = Config.read(provider);
        byte[] data = provider.consumeRemainingAsBytes();
        Lz4FuzzSupport.runWithCpuLimit(data.length, INPUT_CPU_TIME, () -> run(Lz4FuzzSupport.codecs(), config, data));
    }

    static void run(List<Codec> codecs, Config config, byte[] data) {
        switch (config.mode()) {
            case MODE_BLOCK_DECODE -> decode(codecs, config, data, false);
            case MODE_FRAME_DECODE -> decode(codecs, config, data, true);
            case MODE_BLOCK_ROUND_TRIP -> roundTrip(codecs, config, data, false);
            case MODE_FRAME_ROUND_TRIP -> roundTrip(codecs, config, data, true);
            default -> throw new IllegalArgumentException("Unknown mode " + config.mode());
        }
    }

    private static void decode(List<Codec> codecs, Config config, byte[] data, boolean frame) {
        StreamResult reference = null;
        for (Codec codec : codecs) {
            StreamResult result = frame ? decodeFrameStream(codec, config, data, true) : decodeBlockStream(codec, config, data, true);
            if (reference == null) {
                reference = result;
            } else if (!(codec.nativeCode() ? result.consistentWith(reference) : result.sameAs(reference))) {
                throw new AssertionError(codec.name() + " decoded " + result + " but " + codecs.get(0).name() + " decoded " + reference);
            }
        }
    }

    private static void roundTrip(List<Codec> codecs, Config config, byte[] input, boolean frame) {
        // readAll stops at MAX_OUTPUT, so the expected output must fit
        byte[] data = input.length > MAX_OUTPUT / 2 ? Arrays.copyOf(input, MAX_OUTPUT / 2) : input;
        boolean concatenate = config.has(FLAG_CONCATENATE);
        boolean singleStream = frame ? config.has(FLAG_READ_SINGLE_FRAME) : config.has(FLAG_STOP_ON_EMPTY_BLOCK);
        byte[] expected = concatenate && !singleStream ? concat(data, data) : data;
        for (Codec encoder : codecs) {
            byte[] encoded = frame ? encodeFrameStream(encoder, config, data) : encodeBlockStream(encoder, config, data);
            byte[] stream = concatenate ? concat(encoded, encoded) : encoded;
            for (Codec decoder : codecs) {
                StreamResult result = frame ? decodeFrameStream(decoder, config, stream, false) : decodeBlockStream(decoder, config, stream, false);
                if (result.error() != null || !Arrays.equals(expected, result.output())) {
                    throw new AssertionError(decoder.name() + " decoded " + result + " from " + encoder.name() + " stream "
                        + Lz4FuzzSupport.hex(stream) + ", expected " + Lz4FuzzSupport.hex(expected), result.error());
                }
            }
        }
    }

    private static StreamResult decodeBlockStream(Codec codec, Config config, byte[] data, boolean allowSkip) {
        StreamingXXHash32 checksum = codec.hashes().newStreamingHash32(BLOCK_SEED);
        LZ4BlockInputStream in = LZ4BlockInputStream.newBuilder()
            .withDecompressor(codec.safeDecompressor())
            .withChecksum(checksum.asChecksum())
            .withStopOnEmptyBlock(config.has(FLAG_STOP_ON_EMPTY_BLOCK))
            .withAcceptOversizedBlocks(config.has(FLAG_ACCEPT_OVERSIZED_BLOCKS) && !hasOversizedBlock(data))
            .build(new ByteArrayInputStream(data));
        try (checksum; in) {
            return readAll(in, config, allowSkip, false, -1);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Walks the block headers like {@link LZ4BlockInputStream} and checks whether any of them
     * declares a compressed length that is larger than the whole input.
     */
    static boolean hasOversizedBlock(byte[] data) {
        int pos = 0;
        while (pos <= data.length - BLOCK_HEADER_LENGTH) {
            if (!Arrays.equals(data, pos, pos + BLOCK_MAGIC_LENGTH, BLOCK_MAGIC, 0, BLOCK_MAGIC_LENGTH)) {
                return false;
            }
            int compressedLen = Lz4FuzzSupport.readIntLE(data, pos + BLOCK_MAGIC_LENGTH + 1);
            if (compressedLen < 0 || compressedLen > data.length) {
                return true;
            }
            pos += BLOCK_HEADER_LENGTH + compressedLen;
        }
        return false;
    }

    private static StreamResult decodeFrameStream(Codec codec, Config config, byte[] data, boolean allowSkip) {
        boolean singleFrame = config.has(FLAG_READ_SINGLE_FRAME);
        try (LZ4FrameInputStream in = new LZ4FrameInputStream(new ByteArrayInputStream(data), codec.safeDecompressor(), codec.hashes().hash32(), singleFrame)) {
            long expectedSize = -1;
            if (singleFrame && config.has(FLAG_QUERY_CONTENT_SIZE)) {
                try {
                    expectedSize = in.getExpectedContentSize();
                } catch (IOException e) {
                    checkException(e, true);
                    checkStillFailing(in, e);
                    return new StreamResult(new byte[0], 0, e);
                }
            }
            return readAll(in, config, allowSkip, true, expectedSize);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static StreamResult readAll(InputStream in, Config config, boolean allowSkip, boolean frame, long expectedSize) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[MAX_CHUNK_SIZE];
        long position = 0;
        boolean eof = false;
        try {
            for (int i = 0; output.size() < MAX_OUTPUT && !eof; i++) {
                int size = config.chunkSizes()[i % CHUNK_SIZES];
                if (size == 0) {
                    int b = in.read();
                    if (b < 0) {
                        eof = true;
                    } else {
                        output.write(b);
                        position++;
                    }
                } else if (allowSkip && config.has(FLAG_SKIP) && i % SKIP_INTERVAL == SKIP_INTERVAL - 1) {
                    long skipped = in.skip(size);
                    Lz4FuzzSupport.checkLength(in, "skip", (int) skipped, size);
                    eof = skipped == 0;
                    position += skipped;
                } else {
                    int n = in.read(buffer, 0, size);
                    if (n < 0) {
                        eof = true;
                    } else {
                        Lz4FuzzSupport.checkLength(in, "read", n, size);
                        output.write(buffer, 0, n);
                        position += n;
                    }
                }
                if (in.available() < 0) {
                    throw new AssertionError("Negative available()");
                }
            }
        } catch (IOException e) {
            checkException(e, frame);
            checkStillFailing(in, e);
            return new StreamResult(output.toByteArray(), position, e);
        }
        if (eof && expectedSize >= 0 && position != expectedSize) {
            throw new AssertionError("Frame declared content size " + expectedSize + " but decoded " + position + " bytes");
        }
        return new StreamResult(output.toByteArray(), position, null);
    }

    /**
     * Checks that a decoding failure is caused by invalid input and not by a bug.
     */
    static void checkException(IOException e, boolean frame) {
        Throwable wrapper = e;
        for (Throwable cause = e.getCause(); cause != null; wrapper = cause, cause = cause.getCause()) {
            if (!(cause instanceof IOException || cause instanceof LZ4Exception || frame && isDescriptorValidation(wrapper, cause))) {
                throw new AssertionError("Unexpected exception wrapped in an IOException", e);
            }
        }
    }

    /**
     * {@code LZ4FrameOutputStream.FLG}, {@code BD} and {@code BLOCKSIZE} reject invalid frame
     * descriptors with a {@link RuntimeException} or {@link IllegalArgumentException}, which
     * {@code LZ4FrameInputStream.readHeader} wraps in an {@link IOException}. Only exactly that
     * case is accepted.
     */
    private static boolean isDescriptorValidation(Throwable wrapper, Throwable cause) {
        if (wrapper.getClass() != IOException.class || !INVALID_DESCRIPTOR.equals(wrapper.getMessage())
            || !thrownBy(wrapper, LZ4FrameInputStream.class, "readHeader") || cause.getCause() != null) {
            return false;
        }
        if (cause.getClass() == RuntimeException.class) {
            return thrownBy(cause, LZ4FrameOutputStream.FLG.class, "validate") || thrownBy(cause, LZ4FrameOutputStream.BD.class, "fromByte");
        }
        return cause.getClass() == IllegalArgumentException.class && thrownBy(cause, LZ4FrameOutputStream.BLOCKSIZE.class, "valueOf");
    }

    private static boolean thrownBy(Throwable t, Class<?> type, String method) {
        StackTraceElement[] trace = t.getStackTrace();
        return trace.length > 0 && trace[0].getClassName().equals(type.getName()) && trace[0].getMethodName().equals(method);
    }

    private static void checkStillFailing(InputStream in, IOException original) {
        try {
            int b = in.read();
            throw new AssertionError("read() returned " + b + " after a failure", original);
        } catch (IOException expected) {
            // a failed stream must not continue with inconsistent state
        }
    }

    private static byte[] encodeBlockStream(Codec codec, Config config, byte[] data) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (StreamingXXHash32 checksum = codec.hashes().newStreamingHash32(BLOCK_SEED)) {
            LZ4BlockOutputStream out = new LZ4BlockOutputStream(bytes, config.blockSize(), compressor(codec, config), checksum.asChecksum(), config.has(FLAG_SYNC_FLUSH));
            writeAll(out, config, data);
            if (config.has(FLAG_FINISH)) {
                out.finish();
            }
            out.close();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return bytes.toByteArray();
    }

    private static byte[] encodeFrameStream(Codec codec, Config config, byte[] data) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        List<LZ4FrameOutputStream.FLG.Bits> bits = new ArrayList<>();
        bits.add(LZ4FrameOutputStream.FLG.Bits.BLOCK_INDEPENDENCE);
        if (config.has(FLAG_CONTENT_CHECKSUM)) {
            bits.add(LZ4FrameOutputStream.FLG.Bits.CONTENT_CHECKSUM);
        }
        if (config.has(FLAG_BLOCK_CHECKSUM)) {
            bits.add(LZ4FrameOutputStream.FLG.Bits.BLOCK_CHECKSUM);
        }
        long knownSize = -1;
        if (config.has(FLAG_CONTENT_SIZE)) {
            bits.add(LZ4FrameOutputStream.FLG.Bits.CONTENT_SIZE);
            knownSize = data.length;
        }
        // block sizes much larger than the data only cost allocations
        int sizeIndex = 0;
        while (sizeIndex < 3 && MIN_FRAME_BLOCK_SIZE << (2 * sizeIndex) < data.length) {
            sizeIndex++;
        }
        sizeIndex = Math.min(sizeIndex, (config.flags() >> FRAME_BLOCK_SIZE_SHIFT) & 3);
        LZ4FrameOutputStream.BLOCKSIZE blockSize = LZ4FrameOutputStream.BLOCKSIZE.values()[sizeIndex];
        try (LZ4FrameOutputStream out = new LZ4FrameOutputStream(bytes, blockSize, knownSize, compressor(codec, config), codec.hashes().hash32(),
            bits.toArray(new LZ4FrameOutputStream.FLG.Bits[0]))) {
            writeAll(out, config, data);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return bytes.toByteArray();
    }

    private static LZ4Compressor compressor(Codec codec, Config config) {
        return config.has(FLAG_HIGH_COMPRESSION) ? codec.highCompressor().apply(config.level()) : codec.fastCompressor();
    }

    private static void writeAll(OutputStream out, Config config, byte[] data) throws IOException {
        int pos = 0;
        for (int i = 0; pos < data.length; i++) {
            int size = Math.min(config.chunkSizes()[i % CHUNK_SIZES], data.length - pos);
            if (size == 0) {
                out.write(data[pos]);
                pos++;
            } else {
                out.write(data, pos, size);
                pos += size;
            }
            if (config.has(FLAG_FLUSH)) {
                out.flush();
            }
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(Lz4StreamTarget.class).fuzz();
    }

    /**
     * Result of decoding a stream.
     *
     * @param output   The bytes that were read
     * @param position The number of bytes that were read or skipped
     * @param error    The failure, if any
     */
    record StreamResult(byte[] output, long position, @Nullable IOException error) {
        boolean sameAs(StreamResult other) {
            return Arrays.equals(output, other.output) && position == other.position
                && (error == null ? other.error == null : other.error != null && error.getClass() == other.error.getClass());
        }

        /**
         * @return Whether both results decoded the same data up to the first failure. Two results
         * without failure must be the same.
         */
        boolean consistentWith(StreamResult other) {
            if (error == null && other.error == null) {
                return sameAs(other);
            }
            boolean thisFailedFirst = error != null && (other.error == null || position <= other.position);
            StreamResult shorter = thisFailedFirst ? this : other;
            StreamResult longer = thisFailedFirst ? other : this;
            return shorter.position <= longer.position && shorter.output.length <= longer.output.length
                && Arrays.equals(shorter.output, 0, shorter.output.length, longer.output, 0, shorter.output.length);
        }

        @Override
        public String toString() {
            return "StreamResult[output=" + Lz4FuzzSupport.hex(output) + ", position=" + position + ", error=" + error + "]";
        }
    }

    /**
     * Configuration of one input.
     *
     * @param mode       One of the {@code MODE_} constants
     * @param flags      Combination of the {@code FLAG_} constants and the frame block size
     * @param blockSize  The block size of {@link LZ4BlockOutputStream}
     * @param level      The compression level for {@link #FLAG_HIGH_COMPRESSION}
     * @param chunkSizes Sizes of the reads and writes, used in a cycle. 0 means a single byte read
     *                   or write.
     */
    record Config(int mode, int flags, int blockSize, int level, int[] chunkSizes) {
        static Config read(FuzzedDataProvider provider) {
            int mode = provider.consumeInt(MODE_BLOCK_DECODE, MODE_FRAME_ROUND_TRIP);
            int flags = provider.consumeInt(0, (1 << (FRAME_BLOCK_SIZE_SHIFT + 2)) - 1);
            int blockSize = provider.consumeInt(MIN_BLOCK_SIZE, MAX_BLOCK_SIZE);
            int level = provider.consumeInt(-1, 18);
            int[] chunkSizes = new int[CHUNK_SIZES];
            for (int i = 0; i < CHUNK_SIZES; i++) {
                chunkSizes[i] = provider.consumeInt(0, MAX_CHUNK_SIZE);
            }
            return new Config(mode, flags, blockSize, level, chunkSizes);
        }

        boolean has(int flag) {
            return (flags & flag) != 0;
        }
    }
}

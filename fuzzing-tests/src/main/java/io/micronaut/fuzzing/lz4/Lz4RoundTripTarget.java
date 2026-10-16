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
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.lz4.Lz4FuzzSupport.BufferKind;
import io.micronaut.fuzzing.lz4.Lz4FuzzSupport.Codec;
import io.micronaut.fuzzing.lz4.Lz4FuzzSupport.Outcome;
import io.micronaut.fuzzing.lz4.Lz4FuzzSupport.Region;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import net.jpountz.lz4.LZ4Compressor;
import net.jpountz.lz4.LZ4CompressorWithLength;
import net.jpountz.lz4.LZ4DecompressorWithLength;
import net.jpountz.lz4.LZ4Exception;
import net.jpountz.lz4.LZ4Factory;
import net.jpountz.lz4.LZ4FastDecompressor;
import net.jpountz.lz4.LZ4JNIFastResetCompressor;
import net.jpountz.lz4.LZ4JNIHCFastResetCompressor;

import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.List;

/**
 * Round trip fuzz target for LZ4 block compression.
 *
 * <p>The input is compressed with every compressor of every implementation (fast, high with a
 * fuzzed level, and for JNI also the fast-reset compressors, both freshly created and reused
 * across inputs), through the array and the {@link java.nio.ByteBuffer} API, into a destination
 * that is either large enough or of a fuzzed smaller size. Oracles:
 * <ul>
 *     <li>Compression succeeds if the destination has {@code maxCompressedLength} bytes, and
 *     otherwise either succeeds or throws {@link LZ4Exception}.</li>
 *     <li>The compressed length does not exceed the destination size or {@code maxCompressedLength},
 *     no bytes outside of the destination region are written, and the source is not modified.</li>
 *     <li>The safe decompressor of every implementation and the fast decompressor restore the
 *     input from the compressed data.</li>
 *     <li>{@link LZ4CompressorWithLength} and {@link LZ4DecompressorWithLength} round trip.</li>
 * </ul>
 */
@FuzzTarget
@Dict({
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "abcdabcdabcdabcd", "\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000",
    "0123456789012345", "hello world hello world",
})
public final class Lz4RoundTripTarget {
    private static final long INPUT_CPU_TIME = 200;
    private static final int DECOMPRESS_SLACK = 16;

    private Lz4RoundTripTarget() {
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider provider) {
        Config config = Config.read(provider);
        byte[] data = provider.consumeRemainingAsBytes();
        Lz4FuzzSupport.runWithCpuLimit(data.length, INPUT_CPU_TIME, () -> run(Lz4FuzzSupport.codecs(), config, data));
    }

    static void run(List<Codec> codecs, Config config, byte[] data) {
        Lz4FuzzSupport.resetDirectBuffers();
        for (int i = 0; i < codecs.size(); i++) {
            Codec codec = codecs.get(i);
            roundTrip(codecs, i, codec.name() + " fast", codec.fastCompressor(), config, data);
            roundTrip(codecs, i, codec.name() + " high(" + config.level() + ")", codec.highCompressor().apply(config.level()), config, data);
            LZ4Factory factory = codec.factory();
            if (codec.nativeCode() && factory != null) {
                try (LZ4JNIFastResetCompressor compressor = factory.fastResetCompressor(config.acceleration())) {
                    roundTrip(codecs, i, codec.name() + " fastReset(" + config.acceleration() + ")", compressor, config, data);
                }
                try (LZ4JNIHCFastResetCompressor compressor = factory.highFastResetCompressor(config.level())) {
                    roundTrip(codecs, i, codec.name() + " highFastReset(" + config.level() + ")", compressor, config, data);
                }
                // reused across inputs, to check that the state is reset properly
                roundTrip(codecs, i, codec.name() + " shared fastReset", SharedCompressors.FAST, config, data);
                roundTrip(codecs, i, codec.name() + " shared highFastReset", SharedCompressors.HIGH, config, data);
            }
            byte[] withLength = new LZ4CompressorWithLength(codec.fastCompressor()).compress(data);
            for (Codec decoder : codecs) {
                byte[] restored;
                try {
                    restored = new LZ4DecompressorWithLength(decoder.safeDecompressor()).decompress(withLength);
                } catch (LZ4Exception e) {
                    throw new AssertionError(decoder.name() + " LZ4DecompressorWithLength failed on output of " + codec.name() + " LZ4CompressorWithLength", e);
                }
                if (!Arrays.equals(data, restored)) {
                    checkRestored(decoder.name() + " LZ4DecompressorWithLength of " + codec.name() + " LZ4CompressorWithLength", data, restored);
                }
            }
        }
    }

    private static void roundTrip(List<Codec> codecs, int codecIndex, String name, LZ4Compressor compressor, Config config, byte[] data) {
        int bound = compressor.maxCompressedLength(data.length);
        int maxDestLen = config.limitOutput() ? Math.min(config.maxDestLen(), bound) : bound;
        Outcome arrayOutcome = compressArray(codecIndex, name, compressor, config, data, bound, maxDestLen);
        Outcome bufferOutcome = compressBuffer(codecIndex, name, compressor, config, data, bound, maxDestLen);
        if (arrayOutcome.succeeded()) {
            checkDecompresses(codecs, name, arrayOutcome.output(), data);
        }
        if (bufferOutcome.succeeded() && !bufferOutcome.sameAs(arrayOutcome)) {
            checkDecompresses(codecs, name, bufferOutcome.output(), data);
        }
    }

    private static Outcome compressArray(int codecIndex, String name, LZ4Compressor compressor, Config config, byte[] data, int bound, int maxDestLen) {
        String operation = "compress(byte[])";
        Region src = Region.array(config.srcOff() + data.length + config.srcTail(), Lz4FuzzSupport.srcFill(codecIndex))
            .put(config.srcOff(), data);
        Region dest = Region.array(config.destOff() + maxDestLen + config.destTail(), Lz4FuzzSupport.destCanary(codecIndex));
        byte[] srcBefore = src.snapshot();
        byte[] destBefore = dest.snapshot();
        Outcome outcome;
        try {
            int n = compressor.compress(src.array(), config.srcOff(), data.length, dest.array(), config.destOff(), maxDestLen);
            Lz4FuzzSupport.checkLength(name, operation, n, Math.min(maxDestLen, bound));
            outcome = Outcome.success(dest.get(config.destOff(), n));
        } catch (LZ4Exception e) {
            outcome = compressionFailed(name, operation, e, maxDestLen, bound);
        }
        src.checkUnchanged(name, operation, srcBefore);
        dest.checkUnchangedOutside(name, operation, destBefore, config.destOff(), config.destOff() + maxDestLen);
        return outcome;
    }

    private static Outcome compressBuffer(int codecIndex, String name, LZ4Compressor compressor, Config config, byte[] data, int bound, int maxDestLen) {
        String operation = "compress(ByteBuffer)";
        BufferKind srcKind = config.srcKind();
        if (srcKind == BufferKind.READ_ONLY_HEAP && (compressor instanceof LZ4JNIFastResetCompressor || compressor instanceof LZ4JNIHCFastResetCompressor)) {
            srcKind = BufferKind.HEAP; // the fast-reset compressors only support direct or array-backed buffers
        }
        Region src = Region.buffer(srcKind, config.srcShift(), config.srcOff() + data.length + config.srcTail(), config.srcOrder(), Lz4FuzzSupport.srcFill(codecIndex))
            .put(config.srcOff(), data);
        Region dest = Region.buffer(config.destKind(), config.destShift(), config.destOff() + maxDestLen + config.destTail(), config.destOrder(), Lz4FuzzSupport.destCanary(codecIndex));
        byte[] srcBefore = src.snapshot();
        byte[] destBefore = dest.snapshot();
        Outcome outcome;
        try {
            int n = compressor.compress(src.buffer(), config.srcOff(), data.length, dest.buffer(), config.destOff(), maxDestLen);
            Lz4FuzzSupport.checkLength(name, operation, n, Math.min(maxDestLen, bound));
            outcome = Outcome.success(dest.get(config.destOff(), n));
        } catch (LZ4Exception e) {
            outcome = compressionFailed(name, operation, e, maxDestLen, bound);
        }
        src.checkUnchanged(name, operation, srcBefore);
        dest.checkUnchangedOutside(name, operation, destBefore, config.destOff(), config.destOff() + maxDestLen);
        return outcome;
    }

    private static Outcome compressionFailed(String name, String operation, LZ4Exception e, int maxDestLen, int bound) {
        if (maxDestLen >= bound) {
            throw new AssertionError(name + " " + operation + " failed although the destination has maxCompressedLength bytes", e);
        }
        return Outcome.FAILURE;
    }

    private static void checkDecompresses(List<Codec> codecs, String name, byte[] compressed, byte[] data) {
        for (Codec decoder : codecs) {
            for (int maxDestLen : new int[] {data.length, data.length + DECOMPRESS_SLACK}) {
                byte[] restored = new byte[maxDestLen];
                int n;
                try {
                    n = decoder.safeDecompressor().decompress(compressed, 0, compressed.length, restored, 0, maxDestLen);
                } catch (LZ4Exception e) {
                    throw new AssertionError(decompressDescription(decoder, maxDestLen, name, compressed) + " failed", e);
                }
                if (n != data.length || !Arrays.equals(data, 0, n, restored, 0, n)) {
                    checkRestored(decompressDescription(decoder, maxDestLen, name, compressed), data, Arrays.copyOf(restored, n));
                }
            }
        }
        LZ4FastDecompressor fast = LZ4Factory.safeInstance().fastDecompressor();
        byte[] restored = new byte[data.length];
        int consumed;
        try {
            consumed = fast.decompress(compressed, 0, restored, 0, data.length);
        } catch (LZ4Exception e) {
            throw new AssertionError("fast decompressor failed on " + name + " output " + Lz4FuzzSupport.hex(compressed), e);
        }
        if (consumed != compressed.length) {
            throw new AssertionError("fast decompressor consumed " + consumed + " of " + compressed.length + " bytes of " + name + " output");
        }
        if (!Arrays.equals(data, restored)) {
            checkRestored("fast decompressor of " + name + " output", data, restored);
        }
    }

    private static String decompressDescription(Codec decoder, int maxDestLen, String name, byte[] compressed) {
        return decoder.name() + " decompress(maxDestLen=" + maxDestLen + ") of " + name + " output " + Lz4FuzzSupport.hex(compressed);
    }

    private static void checkRestored(String what, byte[] expected, byte[] actual) {
        if (!Arrays.equals(expected, actual)) {
            throw new AssertionError(what + " restored " + Lz4FuzzSupport.hex(actual) + ", expected " + Lz4FuzzSupport.hex(expected));
        }
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(Lz4RoundTripTarget.class).fuzz();
    }

    /**
     * Configuration of one input.
     *
     * @param level        The compression level of the high compressors
     * @param acceleration The acceleration of the fast-reset compressor
     * @param limitOutput  Whether to use {@code maxDestLen} instead of {@code maxCompressedLength}
     * @param maxDestLen   The destination size if {@code limitOutput} is set
     * @param srcOff       Offset of the input in the source
     * @param srcTail      Number of bytes after the input in the source
     * @param destOff      Offset of the output in the destination
     * @param destTail     Number of bytes after {@code maxDestLen} in the destination
     * @param srcShift     Offset of the source buffer in its parent buffer
     * @param destShift    Offset of the destination buffer in its parent buffer
     * @param srcKind      Kind of the source buffer
     * @param destKind     Kind of the destination buffer
     * @param srcOrder     Byte order of the source buffer
     * @param destOrder    Byte order of the destination buffer
     */
    record Config(
        int level,
        int acceleration,
        boolean limitOutput,
        int maxDestLen,
        int srcOff,
        int srcTail,
        int destOff,
        int destTail,
        int srcShift,
        int destShift,
        BufferKind srcKind,
        BufferKind destKind,
        ByteOrder srcOrder,
        ByteOrder destOrder
    ) {
        static Config read(FuzzedDataProvider provider) {
            // out of range levels and accelerations are clamped by lz4-java
            int level = provider.consumeInt(-1, 18);
            int acceleration = provider.consumeInt(-1, 1 << 17);
            int maxDestLen = provider.consumeInt(0, Lz4FuzzSupport.MAX_DEST_LENGTH);
            int srcOff = provider.consumeInt(0, Lz4FuzzSupport.MAX_PADDING);
            int srcTail = provider.consumeInt(0, Lz4FuzzSupport.MAX_PADDING);
            int destOff = provider.consumeInt(0, Lz4FuzzSupport.MAX_PADDING);
            int destTail = provider.consumeInt(0, Lz4FuzzSupport.MAX_PADDING);
            int srcShift = provider.consumeInt(0, Lz4FuzzSupport.MAX_SHIFT);
            int destShift = provider.consumeInt(0, Lz4FuzzSupport.MAX_SHIFT);
            int flags = provider.consumeInt(0, 0xFF);
            return new Config(
                level, acceleration, (flags & 0x40) != 0, maxDestLen, srcOff, srcTail, destOff, destTail, srcShift, destShift,
                BufferKind.fromBits(flags & 3, true),
                BufferKind.fromBits((flags >> 2) & 1, false),
                (flags & 0x10) != 0 ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN,
                (flags & 0x20) != 0 ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN
            );
        }
    }

    /**
     * Native fast-reset compressors that are reused for all inputs. They are only created if the
     * native library is available.
     */
    private static final class SharedCompressors {
        @Nullable
        private static final LZ4Factory NATIVE = Lz4FuzzSupport.isNativeAvailable() ? LZ4Factory.nativeInstance() : null;
        private static final LZ4JNIFastResetCompressor FAST = NATIVE == null ? null : NATIVE.fastResetCompressor();
        private static final LZ4JNIHCFastResetCompressor HIGH = NATIVE == null ? null : NATIVE.highFastResetCompressor();
    }
}

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
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.DictResource;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.lz4.Lz4FuzzSupport.BufferKind;
import io.micronaut.fuzzing.lz4.Lz4FuzzSupport.Codec;
import io.micronaut.fuzzing.lz4.Lz4FuzzSupport.Outcome;
import io.micronaut.fuzzing.lz4.Lz4FuzzSupport.Region;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import net.jpountz.lz4.LZ4DecompressorWithLength;
import net.jpountz.lz4.LZ4Exception;
import net.jpountz.lz4.LZ4Factory;
import net.jpountz.lz4.LZ4FastDecompressor;
import net.jpountz.lz4.LZ4SafeDecompressor;

import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.List;

/**
 * Differential fuzz target for LZ4 block decompression of untrusted input.
 *
 * <p>The input is decompressed with the safe decompressor of every implementation (Java safe,
 * Java {@code Unsafe} and JNI if it can be loaded), through the array and the {@link java.nio.ByteBuffer}
 * API, with nonzero offsets. The only accepted exception is {@link LZ4Exception}. Oracles:
 * <ul>
 *     <li>All implementations and API variants produce the same output, or all reject the input.
 *     The native and the Java implementations disagree about some invalid blocks, so for the
 *     native implementation only the output is compared if both accept the input. The native
 *     {@link java.nio.ByteBuffer} variant must agree exactly with the native array variant.</li>
 *     <li>No bytes outside of {@code dest[destOff, destOff + maxDestLen)} are written, the source
 *     is not modified, and the buffer positions do not move.</li>
 *     <li>The (secure) fast decompressor decodes the same data when the safe decompressor
 *     fills the whole destination.</li>
 *     <li>{@link LZ4DecompressorWithLength} agrees with the safe decompressor and the length prefix.</li>
 * </ul>
 */
@FuzzTarget
@Dict({
    "\u0000", "\u0010", "\u001f", "\u0001\u0000", "\u0004\u0000", "\u000f\u0000", "@\u0000\u0000\u0000",
})
@DictResource("io/micronaut/fuzzing/lz4/lz4.dict")
public final class Lz4BlockDecompressorTarget {
    private static final long INPUT_CPU_TIME = 50;
    private static final int LENGTH_PREFIX = 4;

    private Lz4BlockDecompressorTarget() {
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider provider) {
        Config fuzzedConfig = Config.read(provider);
        byte[] compressed = provider.consumeRemainingAsBytes();
        // larger destinations than the maximum decompressed size only slow down the fuzzer
        int maxUsefulDestLen = Lz4FuzzSupport.MAX_COMPRESSION_RATIO * compressed.length + Lz4FuzzSupport.MAX_PADDING;
        Config config = fuzzedConfig.withMaxDestLen(Math.min(fuzzedConfig.maxDestLen(), maxUsefulDestLen));
        Lz4FuzzSupport.runWithCpuLimit(compressed.length, INPUT_CPU_TIME, () -> run(Lz4FuzzSupport.codecs(), config, compressed));
    }

    static void run(List<Codec> codecs, Config config, byte[] compressed) {
        Lz4FuzzSupport.resetDirectBuffers();
        Codec reference = codecs.get(0);
        Outcome referenceOutcome = decompressArray(reference.safeDecompressor(), 0, config, compressed, config.maxDestLen());
        for (int i = 0; i < codecs.size(); i++) {
            Codec codec = codecs.get(i);
            Outcome arrayOutcome = i == 0 ? referenceOutcome : decompressArray(codec.safeDecompressor(), i, config, compressed, config.maxDestLen());
            Outcome bufferOutcome = decompressBuffer(codec.safeDecompressor(), i, config, compressed, config.maxDestLen());
            Lz4FuzzSupport.compare(codec.name(), "decompress(byte[])", referenceOutcome, arrayOutcome, codec.nativeCode());
            // The native buffer variant uses the same C decoder as the array variant, except for
            // buffers that are neither array-backed nor direct, where it falls back to Java.
            Outcome bufferReference = codec.nativeCode() && config.srcKind() != BufferKind.READ_ONLY_HEAP ? arrayOutcome : referenceOutcome;
            Lz4FuzzSupport.compare(codec.name(), "decompress(ByteBuffer)", bufferReference, bufferOutcome, false);
            if (compressed.length >= LENGTH_PREFIX) {
                checkWithLength(codec, i, config, compressed);
            }
        }
        checkFastDecompressor(LZ4Factory.safeInstance().fastDecompressor(), config, compressed, referenceOutcome);
    }

    private static Region sourceArray(int codecIndex, Config config, byte[] compressed) {
        return Region.array(config.srcOff() + compressed.length + config.srcTail(), Lz4FuzzSupport.srcFill(codecIndex))
            .put(config.srcOff(), compressed);
    }

    private static Region sourceBuffer(int codecIndex, Config config, byte[] compressed) {
        return Region.buffer(config.srcKind(), config.srcShift(), config.srcOff() + compressed.length + config.srcTail(), config.srcOrder(), Lz4FuzzSupport.srcFill(codecIndex))
            .put(config.srcOff(), compressed);
    }

    private static Outcome decompressArray(LZ4SafeDecompressor decompressor, int codecIndex, Config config, byte[] compressed, int maxDestLen) {
        Region src = sourceArray(codecIndex, config, compressed);
        Region dest = Region.array(config.destOff() + maxDestLen + config.destTail(), Lz4FuzzSupport.destCanary(codecIndex));
        byte[] srcBefore = src.snapshot();
        byte[] destBefore = dest.snapshot();
        Outcome outcome;
        try {
            int n = decompressor.decompress(src.array(), config.srcOff(), compressed.length, dest.array(), config.destOff(), maxDestLen);
            Lz4FuzzSupport.checkLength(decompressor, "decompress(byte[])", n, maxDestLen);
            outcome = Outcome.success(dest.get(config.destOff(), n));
        } catch (LZ4Exception e) {
            outcome = Outcome.FAILURE;
        }
        src.checkUnchanged(decompressor, "decompress(byte[]) source", srcBefore);
        dest.checkUnchangedOutside(decompressor, "decompress(byte[])", destBefore, config.destOff(), config.destOff() + maxDestLen);
        return outcome;
    }

    private static Outcome decompressBuffer(LZ4SafeDecompressor decompressor, int codecIndex, Config config, byte[] compressed, int maxDestLen) {
        Region src = sourceBuffer(codecIndex, config, compressed);
        Region dest = Region.buffer(config.destKind(), config.destShift(), config.destOff() + maxDestLen + config.destTail(), config.destOrder(), Lz4FuzzSupport.destCanary(codecIndex));
        byte[] srcBefore = src.snapshot();
        byte[] destBefore = dest.snapshot();
        Outcome outcome;
        try {
            int n = decompressor.decompress(src.buffer(), config.srcOff(), compressed.length, dest.buffer(), config.destOff(), maxDestLen);
            Lz4FuzzSupport.checkLength(decompressor, "decompress(ByteBuffer)", n, maxDestLen);
            outcome = Outcome.success(dest.get(config.destOff(), n));
        } catch (LZ4Exception e) {
            outcome = Outcome.FAILURE;
        }
        src.checkUnchanged(decompressor, "decompress(ByteBuffer) source", srcBefore);
        dest.checkUnchangedOutside(decompressor, "decompress(ByteBuffer)", destBefore, config.destOff(), config.destOff() + maxDestLen);
        return outcome;
    }

    /**
     * The fast decompressor decodes until it has produced exactly {@code destLen} bytes, so it is
     * only comparable to the safe decompressor if that one filled the whole destination. In that
     * case both take the same path through the input and must agree. Otherwise the fast
     * decompressor may legitimately reject the input, but must still stay in bounds.
     */
    private static void checkFastDecompressor(LZ4FastDecompressor decompressor, Config config, byte[] compressed, Outcome safeOutcome) {
        int destLen = config.maxDestLen();
        Region src = sourceArray(0, config, compressed);
        Region dest = Region.array(config.destOff() + destLen + config.destTail(), Lz4FuzzSupport.destCanary(0));
        byte[] srcBefore = src.snapshot();
        byte[] destBefore = dest.snapshot();
        Outcome outcome;
        int consumed = -1;
        try {
            consumed = decompressor.decompress(src.array(), config.srcOff(), dest.array(), config.destOff(), destLen);
            Lz4FuzzSupport.checkLength(decompressor, "decompress", consumed, src.size() - config.srcOff());
            outcome = Outcome.success(dest.get(config.destOff(), destLen));
        } catch (LZ4Exception e) {
            outcome = Outcome.FAILURE;
        }
        src.checkUnchanged(decompressor, "source", srcBefore);
        dest.checkUnchangedOutside(decompressor, "decompress", destBefore, config.destOff(), config.destOff() + destLen);
        if (safeOutcome.succeeded() && safeOutcome.output().length == destLen) {
            Lz4FuzzSupport.compare(decompressor, "decompress", safeOutcome, outcome, false);
            if (consumed != compressed.length) {
                throw new AssertionError("fast decompressor consumed " + consumed + " bytes, expected " + compressed.length);
            }
        }
    }

    /**
     * Checks {@link LZ4DecompressorWithLength} against the plain safe decompressor. Inputs shorter
     * than the length prefix are not passed to it, because it reads the prefix before checking
     * the length.
     */
    private static void checkWithLength(Codec codec, int codecIndex, Config config, byte[] input) {
        LZ4SafeDecompressor decompressor = codec.safeDecompressor();
        LZ4DecompressorWithLength withLength = new LZ4DecompressorWithLength(decompressor, Lz4FuzzSupport.MAX_DEST_LENGTH);
        int declared = Lz4FuzzSupport.readIntLE(input, 0);
        byte[] payload = Arrays.copyOfRange(input, LENGTH_PREFIX, input.length);

        // byte[] decompress(byte[], int, int): bounded by the configured maximum and the compression ratio
        boolean declaredValid = declared >= 0 && declared <= Lz4FuzzSupport.MAX_DEST_LENGTH
            && declared <= (long) payload.length * Lz4FuzzSupport.MAX_COMPRESSION_RATIO;
        Outcome expected = declaredValid ? exactly(decompressArray(decompressor, codecIndex, config, payload, declared), declared) : Outcome.FAILURE;
        Region src = sourceArray(codecIndex, config, input);
        byte[] srcBefore = src.snapshot();
        Outcome actual;
        try {
            actual = Outcome.success(withLength.decompress(src.array(), config.srcOff(), input.length));
        } catch (LZ4Exception e) {
            actual = Outcome.FAILURE;
        }
        src.checkUnchanged(codec.name(), "LZ4DecompressorWithLength source", srcBefore);
        Lz4FuzzSupport.compare(codec.name(), "LZ4DecompressorWithLength.decompress(byte[])", expected, actual, false);

        // int decompress(ByteBuffer, int, int, ByteBuffer, int): bounded by the destination capacity
        // the native implementation falls back to Java for some buffer kinds, so compare with the same kinds
        int maxDestLen = config.maxDestLen();
        if (declared >= 0 && declared <= maxDestLen) {
            expected = exactly(decompressBuffer(decompressor, codecIndex, config, payload, declared), declared);
        } else {
            expected = Outcome.FAILURE;
        }
        Region srcBuffer = sourceBuffer(codecIndex, config, input);
        Region dest = Region.buffer(config.destKind(), config.destShift(), config.destOff() + maxDestLen, config.destOrder(), Lz4FuzzSupport.destCanary(codecIndex));
        srcBefore = srcBuffer.snapshot();
        byte[] destBefore = dest.snapshot();
        try {
            int n = withLength.decompress(srcBuffer.buffer(), config.srcOff(), input.length, dest.buffer(), config.destOff());
            Lz4FuzzSupport.checkLength(codec.name(), "LZ4DecompressorWithLength.decompress(ByteBuffer)", n, maxDestLen);
            actual = Outcome.success(dest.get(config.destOff(), n));
        } catch (LZ4Exception e) {
            actual = Outcome.FAILURE;
        }
        srcBuffer.checkUnchanged(codec.name(), "LZ4DecompressorWithLength source", srcBefore);
        dest.checkUnchangedOutside(codec.name(), "LZ4DecompressorWithLength.decompress(ByteBuffer)", destBefore, config.destOff(), config.destOff() + maxDestLen);
        Lz4FuzzSupport.compare(codec.name(), "LZ4DecompressorWithLength.decompress(ByteBuffer)", expected, actual, false);
    }

    private static Outcome exactly(Outcome outcome, int length) {
        return outcome.succeeded() && outcome.output().length == length ? outcome : Outcome.FAILURE;
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(Lz4BlockDecompressorTarget.class).fuzz();
    }

    /**
     * Configuration of one input.
     *
     * @param maxDestLen The maximum decompressed length
     * @param srcOff     Offset of the input in the source
     * @param srcTail    Number of bytes after the input in the source
     * @param destOff    Offset of the output in the destination
     * @param destTail   Number of bytes after {@code maxDestLen} in the destination
     * @param srcShift   Offset of the source buffer in its parent buffer
     * @param destShift  Offset of the destination buffer in its parent buffer
     * @param srcKind    Kind of the source buffer
     * @param destKind   Kind of the destination buffer
     * @param srcOrder   Byte order of the source buffer
     * @param destOrder  Byte order of the destination buffer
     */
    record Config(
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
            int maxDestLen = provider.consumeInt(0, Lz4FuzzSupport.MAX_DEST_LENGTH);
            int srcOff = provider.consumeInt(0, Lz4FuzzSupport.MAX_PADDING);
            int srcTail = provider.consumeInt(0, Lz4FuzzSupport.MAX_PADDING);
            int destOff = provider.consumeInt(0, Lz4FuzzSupport.MAX_PADDING);
            int destTail = provider.consumeInt(0, Lz4FuzzSupport.MAX_PADDING);
            int srcShift = provider.consumeInt(0, Lz4FuzzSupport.MAX_SHIFT);
            int destShift = provider.consumeInt(0, Lz4FuzzSupport.MAX_SHIFT);
            int flags = provider.consumeInt(0, 0xFF);
            return new Config(
                maxDestLen, srcOff, srcTail, destOff, destTail, srcShift, destShift,
                BufferKind.fromBits(flags & 3, true),
                BufferKind.fromBits((flags >> 2) & 1, false),
                (flags & 0x10) != 0 ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN,
                (flags & 0x20) != 0 ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN
            );
        }

        Config withMaxDestLen(int maxDestLen) {
            return new Config(maxDestLen, srcOff, srcTail, destOff, destTail, srcShift, destShift, srcKind, destKind, srcOrder, destOrder);
        }
    }
}

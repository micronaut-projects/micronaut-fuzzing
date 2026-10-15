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
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.lz4.Lz4FuzzSupport.BufferKind;
import io.micronaut.fuzzing.lz4.Lz4FuzzSupport.Codec;
import io.micronaut.fuzzing.lz4.Lz4FuzzSupport.Region;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import net.jpountz.xxhash.StreamingXXHash32;
import net.jpountz.xxhash.StreamingXXHash64;
import net.jpountz.xxhash.XXHash32;
import net.jpountz.xxhash.XXHash64;
import net.jpountz.xxhash.XXHashFactory;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.function.IntFunction;
import java.util.function.LongFunction;
import java.util.zip.Checksum;

/**
 * Differential fuzz target for XXHash32 and XXHash64.
 *
 * <p>The input is hashed with every implementation (Java safe, Java {@code Unsafe} and JNI if it
 * can be loaded), one-shot through the array and the {@link ByteBuffer} API, and streaming in
 * fuzzed chunk sizes. Oracles:
 * <ul>
 *     <li>All implementations and API variants return the same hash.</li>
 *     <li>The streaming value after each chunk equals the one-shot hash of the prefix, also after
 *     {@code reset()} and through {@code asChecksum()}.</li>
 *     <li>The input is not modified, and the absolute {@link ByteBuffer} methods do not move the
 *     position.</li>
 * </ul>
 */
@FuzzTarget
@Dict({"0123456789abcdef", "\u0000\u0000\u0000\u0000"})
public final class XxHashTarget {
    private static final long INPUT_CPU_TIME = 100;
    private static final int CHUNK_SIZES = 4;
    private static final int MAX_CHUNK_SIZE = 300;
    private static final int MAX_PREFIX_CHECKS = 64;
    private static final int CHECKSUM_SINGLE_BYTES = 3;
    /**
     * {@link StreamingXXHash32#asChecksum()} only returns the low 28 bits of the hash. This is a
     * long-standing quirk that is kept for compatibility with the LZ4Block format.
     */
    private static final long CHECKSUM32_MASK = 0x0FFF_FFFFL;

    private XxHashTarget() {
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider provider) {
        Config config = Config.read(provider);
        byte[] data = provider.consumeRemainingAsBytes();
        Lz4FuzzSupport.runWithCpuLimit(data.length, INPUT_CPU_TIME, () -> run(hashers(Lz4FuzzSupport.codecs()), config, data));
    }

    static List<Hasher> hashers(List<Codec> codecs) {
        List<Hasher> hashers = new ArrayList<>(codecs.size());
        for (Codec codec : codecs) {
            hashers.add(Hasher.of(codec.name(), codec.hashes()));
        }
        return hashers;
    }

    static void run(List<Hasher> hashers, Config config, byte[] data) {
        Lz4FuzzSupport.resetDirectBuffers();
        long[] reference = null;
        String referenceName = null;
        for (int i = 0; i < hashers.size(); i++) {
            Hasher hasher = hashers.get(i);
            long[] values = hash(hasher, i, config, data);
            if (reference == null) {
                reference = values;
                referenceName = hasher.name();
            } else if (reference[0] != values[0] || reference[1] != values[1]) {
                throw new AssertionError(hasher.name() + " hashes " + values[0] + "/" + values[1] + " but " + referenceName + " hashes " + reference[0] + "/" + reference[1]);
            }
        }
    }

    private static long[] hash(Hasher hasher, int index, Config config, byte[] data) {
        int off = config.off();
        int len = data.length;
        Region array = Region.array(off + len + config.tail(), Lz4FuzzSupport.srcFill(index)).put(off, data);
        Region buffer = Region.buffer(config.kind(), config.shift(), off + len + config.tail(), config.order(), Lz4FuzzSupport.srcFill(index)).put(off, data);
        byte[] arrayBefore = array.snapshot();
        byte[] bufferBefore = buffer.snapshot();

        int h32 = hasher.hash32().hash(array.array(), off, len, config.seed32());
        long h64 = hasher.hash64().hash(array.array(), off, len, config.seed64());
        check(hasher.name(), "XXHash32 ByteBuffer", h32, hasher.hash32().hash(buffer.buffer(), off, len, config.seed32()));
        check(hasher.name(), "XXHash64 ByteBuffer", h64, hasher.hash64().hash(buffer.buffer(), off, len, config.seed64()));

        // relative variant: hashes position..limit and moves the position to the limit
        ByteBuffer relative = buffer.buffer().duplicate().order(config.order()).limit(off + len).position(off);
        check(hasher.name(), "XXHash32 relative ByteBuffer", h32, hasher.hash32().hash(relative, config.seed32()));
        checkPosition(hasher.name(), "XXHash32 relative ByteBuffer", relative, off + len);
        relative.position(off);
        check(hasher.name(), "XXHash64 relative ByteBuffer", h64, hasher.hash64().hash(relative, config.seed64()));
        checkPosition(hasher.name(), "XXHash64 relative ByteBuffer", relative, off + len);
        buffer.checkUnchanged(hasher.name(), "hash(ByteBuffer)", bufferBefore);

        try (StreamingXXHash32 streaming = hasher.streaming32().apply(config.seed32())) {
            stream(hasher.name(), "StreamingXXHash32", config, array.array(), off, len,
                (b, o, l) -> streaming.update(b, o, l),
                streaming::getValue,
                prefix -> hasher.hash32().hash(array.array(), off, prefix, config.seed32()));
            streaming.reset();
            streaming.update(array.array(), off, len);
            check(hasher.name(), "StreamingXXHash32 after reset", h32, streaming.getValue());
            checkChecksum(hasher.name(), "StreamingXXHash32.asChecksum", streaming.asChecksum(), array.array(), off, len, h32 & CHECKSUM32_MASK);
        }
        try (StreamingXXHash64 streaming = hasher.streaming64().apply(config.seed64())) {
            stream(hasher.name(), "StreamingXXHash64", config, array.array(), off, len,
                (b, o, l) -> streaming.update(b, o, l),
                streaming::getValue,
                prefix -> hasher.hash64().hash(array.array(), off, prefix, config.seed64()));
            streaming.reset();
            streaming.update(array.array(), off, len);
            check(hasher.name(), "StreamingXXHash64 after reset", h64, streaming.getValue());
            checkChecksum(hasher.name(), "StreamingXXHash64.asChecksum", streaming.asChecksum(), array.array(), off, len, h64);
        }
        array.checkUnchanged(hasher.name(), "hash(byte[])", arrayBefore);
        return new long[] {h32, h64};
    }

    private static void stream(String subject, String operation, Config config, byte[] array, int off, int len, Updater updater, ValueSupplier value, PrefixHash prefixHash) {
        int pos = 0;
        int chunk = 0;
        do {
            int size = Math.min(config.chunkSizes()[chunk % CHUNK_SIZES], len - pos);
            updater.update(array, off + pos, size);
            pos += size;
            if (size == 0 && pos < len) {
                // a chunk size of 0 tests empty updates, but must not stall the loop
                updater.update(array, off + pos, 1);
                pos++;
            }
            if (chunk < MAX_PREFIX_CHECKS || pos == len) {
                long expected = prefixHash.hash(pos);
                long actual = value.get();
                if (expected != actual) {
                    check(subject, operation + " after " + pos + " bytes", expected, actual);
                }
            }
            chunk++;
        } while (pos < len);
    }

    private static void checkChecksum(String subject, String operation, Checksum checksum, byte[] array, int off, int len, long expected) {
        checksum.reset();
        int single = Math.min(len, CHECKSUM_SINGLE_BYTES);
        for (int i = 0; i < single; i++) {
            checksum.update(array[off + i]);
        }
        checksum.update(array, off + single, len - single);
        check(subject, operation, expected, checksum.getValue());
    }

    private static void check(String subject, String operation, long expected, long actual) {
        if (expected != actual) {
            throw new AssertionError(subject + " " + operation + " returned " + actual + ", expected " + expected);
        }
    }

    private static void checkPosition(String subject, String operation, ByteBuffer buffer, int expected) {
        if (buffer.position() != expected) {
            throw new AssertionError(subject + " " + operation + " moved the position to " + buffer.position() + ", expected " + expected);
        }
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(XxHashTarget.class).fuzz();
    }

    @FunctionalInterface
    private interface Updater {
        void update(byte[] array, int off, int len);
    }

    @FunctionalInterface
    private interface ValueSupplier {
        long get();
    }

    @FunctionalInterface
    private interface PrefixHash {
        long hash(int length);
    }

    /**
     * One xxhash implementation.
     *
     * @param name        Name for failure messages
     * @param hash32      The one-shot 32-bit hash
     * @param hash64      The one-shot 64-bit hash
     * @param streaming32 The streaming 32-bit hash for a seed
     * @param streaming64 The streaming 64-bit hash for a seed
     */
    record Hasher(
        String name,
        XXHash32 hash32,
        XXHash64 hash64,
        IntFunction<StreamingXXHash32> streaming32,
        LongFunction<StreamingXXHash64> streaming64
    ) {
        static Hasher of(String name, XXHashFactory factory) {
            return new Hasher(name, factory.hash32(), factory.hash64(), factory::newStreamingHash32, factory::newStreamingHash64);
        }
    }

    /**
     * Configuration of one input.
     *
     * @param seed32     The seed of the 32-bit hash
     * @param seed64     The seed of the 64-bit hash
     * @param off        Offset of the input in the array or buffer
     * @param tail       Number of bytes after the input
     * @param shift      Offset of the buffer in its parent buffer
     * @param kind       Kind of the buffer
     * @param order      Byte order of the buffer
     * @param chunkSizes Sizes of the streaming updates, used in a cycle
     */
    record Config(int seed32, long seed64, int off, int tail, int shift, BufferKind kind, ByteOrder order, int[] chunkSizes) {
        static Config read(FuzzedDataProvider provider) {
            int seed32 = provider.consumeInt();
            long seed64 = provider.consumeLong();
            int off = provider.consumeInt(0, Lz4FuzzSupport.MAX_PADDING);
            int tail = provider.consumeInt(0, Lz4FuzzSupport.MAX_PADDING);
            int shift = provider.consumeInt(0, Lz4FuzzSupport.MAX_SHIFT);
            int flags = provider.consumeInt(0, 0xFF);
            int[] chunkSizes = new int[CHUNK_SIZES];
            for (int i = 0; i < CHUNK_SIZES; i++) {
                chunkSizes[i] = provider.consumeInt(0, MAX_CHUNK_SIZE);
            }
            return new Config(seed32, seed64, off, tail, shift, BufferKind.fromBits(flags & 3, true),
                (flags & 4) != 0 ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN, chunkSizes);
        }
    }
}

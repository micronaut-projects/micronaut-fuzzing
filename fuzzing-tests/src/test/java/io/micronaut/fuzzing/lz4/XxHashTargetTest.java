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

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import io.micronaut.fuzzing.lz4.Lz4FuzzSupport.BufferKind;
import net.jpountz.xxhash.XXHash32;
import net.jpountz.xxhash.XXHashFactory;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XxHashTargetTest {
    @Test
    void fuzzesInput() {
        XxHashTarget.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            123, 456L, 3, 4, 5, 0b101, 0, 1, 7, 300, Lz4BlockDecompressorTargetTest.DATA
        )));
    }

    @Test
    void hashesWithAllBufferKindsAndChunkSizes() {
        byte[] random = new byte[1000];
        new Random(0).nextBytes(random);
        for (byte[] data : List.of(new byte[0], new byte[] {1}, Lz4BlockDecompressorTargetTest.DATA, random)) {
            for (int flags = 0; flags < 8; flags++) {
                XxHashTarget.run(XxHashTarget.hashers(Lz4FuzzSupport.codecs()), config(flags, new int[] {flags, 16, 0, 33}), data);
            }
        }
    }

    @Test
    void withoutNative() {
        XxHashTarget.run(XxHashTarget.hashers(Lz4FuzzSupport.javaCodecs()), config(3, new int[] {1, 2, 3, 4}), Lz4BlockDecompressorTargetTest.DATA);
    }

    @Test
    void detectsDifferentHash() {
        XXHash32 delegate = XXHashFactory.safeInstance().hash32();
        XXHash32 broken = new XXHash32() {
            @Override
            public int hash(byte[] buf, int off, int len, int seed) {
                return delegate.hash(buf, off, len, seed) + (len > 10 ? 1 : 0);
            }

            @Override
            public int hash(ByteBuffer buf, int off, int len, int seed) {
                return hash(toArray(buf, off, len), 0, len, seed);
            }
        };
        List<XxHashTarget.Hasher> hashers = new ArrayList<>(XxHashTarget.hashers(Lz4FuzzSupport.javaCodecs()));
        XxHashTarget.Hasher reference = hashers.get(0);
        hashers.add(new XxHashTarget.Hasher("broken", broken, reference.hash64(), reference.streaming32(), reference.streaming64()));
        AssertionError error = assertThrows(AssertionError.class, () -> XxHashTarget.run(hashers, config(0, new int[] {5, 5, 5, 5}), Lz4BlockDecompressorTargetTest.DATA));
        // the one-shot hash of the broken implementation disagrees with its streaming hash
        assertTrue(error.getMessage().contains("broken StreamingXXHash32 after 15 bytes"), error.getMessage());
    }

    @Test
    void detectsDifferentImplementations() {
        // consistent within itself, but different from the other implementations
        XXHashFactory delegate = XXHashFactory.safeInstance();
        XXHash32 broken = new XXHash32() {
            @Override
            public int hash(byte[] buf, int off, int len, int seed) {
                return delegate.hash32().hash(buf, off, len, seed + 1);
            }

            @Override
            public int hash(ByteBuffer buf, int off, int len, int seed) {
                return delegate.hash32().hash(buf, off, len, seed + 1);
            }
        };
        List<XxHashTarget.Hasher> hashers = new ArrayList<>(XxHashTarget.hashers(Lz4FuzzSupport.javaCodecs()));
        hashers.add(new XxHashTarget.Hasher("broken", broken, delegate.hash64(), seed -> delegate.newStreamingHash32(seed + 1), delegate::newStreamingHash64));
        AssertionError error = assertThrows(AssertionError.class, () -> XxHashTarget.run(hashers, config(0, new int[] {5, 5, 5, 5}), Lz4BlockDecompressorTargetTest.DATA));
        assertTrue(error.getMessage().startsWith("broken hashes"), error.getMessage());
    }

    private static byte[] toArray(ByteBuffer buf, int off, int len) {
        byte[] result = new byte[len];
        buf.get(off, result);
        return result;
    }

    private static XxHashTarget.Config config(int flags, int[] chunkSizes) {
        return new XxHashTarget.Config(flags * 31, flags * 1234567890123L, flags % 5, flags % 3, flags % 7,
            BufferKind.fromBits(flags & 3, true), (flags & 4) != 0 ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN, chunkSizes);
    }
}

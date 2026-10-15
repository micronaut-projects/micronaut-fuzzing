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
import io.micronaut.fuzzing.lz4.Lz4FuzzSupport.Codec;
import net.jpountz.lz4.LZ4Compressor;
import net.jpountz.lz4.LZ4Exception;
import net.jpountz.lz4.LZ4Factory;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Lz4RoundTripTargetTest {
    @Test
    void fuzzesInput() {
        Lz4RoundTripTarget.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            9, 1, 0, 2, 3, 4, 5, 6, 7, 0b0011_0101, Lz4BlockDecompressorTargetTest.DATA
        )));
    }

    @Test
    void roundTripsWithAllBufferKinds() {
        byte[] random = new byte[1000];
        new Random(0).nextBytes(random);
        for (byte[] data : List.of(new byte[0], new byte[] {1}, Lz4BlockDecompressorTargetTest.DATA, random, new byte[3000])) {
            for (int flags = 0; flags < 64; flags += 3) {
                Lz4RoundTripTarget.run(Lz4FuzzSupport.codecs(), config(flags % 19 - 1, false, 0, flags), data);
            }
        }
    }

    @Test
    void limitedOutput() {
        byte[] random = new byte[1000];
        new Random(1).nextBytes(random);
        for (byte[] data : List.of(new byte[0], Lz4BlockDecompressorTargetTest.DATA, random)) {
            for (int maxDestLen : new int[] {0, 1, 10, data.length, data.length + 20}) {
                Lz4RoundTripTarget.run(Lz4FuzzSupport.codecs(), config(17, true, maxDestLen, 0b0100), data);
                Lz4RoundTripTarget.run(Lz4FuzzSupport.codecs(), config(3, true, maxDestLen, 0b11_0011), data);
            }
        }
    }

    @Test
    void withoutNative() {
        Lz4RoundTripTarget.run(Lz4FuzzSupport.javaCodecs(), config(9, false, 0, 0b0101), Lz4BlockDecompressorTargetTest.DATA);
    }

    @Test
    void detectsCorruptCompression() {
        LZ4Compressor delegate = LZ4Factory.safeInstance().fastCompressor();
        LZ4Compressor broken = new LZ4Compressor() {
            @Override
            public int compress(byte[] src, int srcOff, int srcLen, byte[] dest, int destOff, int maxDestLen) {
                int n = delegate.compress(src, srcOff, srcLen, dest, destOff, maxDestLen);
                dest[destOff + n - 1]++;
                return n;
            }

            @Override
            public int compress(ByteBuffer src, int srcOff, int srcLen, ByteBuffer dest, int destOff, int maxDestLen) {
                return delegate.compress(src, srcOff, srcLen, dest, destOff, maxDestLen);
            }
        };
        Codec reference = Lz4FuzzSupport.javaCodecs().get(0);
        List<Codec> codecs = List.of(reference, reference.withCompressor(broken));
        AssertionError error = assertThrows(AssertionError.class, () -> Lz4RoundTripTarget.run(codecs, config(9, false, 0, 0), Lz4BlockDecompressorTargetTest.DATA));
        assertTrue(error.getMessage().contains("restored"), error.getMessage());
    }

    @Test
    void detectsFailureWithSufficientDestination() {
        LZ4Compressor delegate = LZ4Factory.safeInstance().fastCompressor();
        LZ4Compressor broken = new LZ4Compressor() {
            @Override
            public int compress(byte[] src, int srcOff, int srcLen, byte[] dest, int destOff, int maxDestLen) {
                throw new LZ4Exception("maxDestLen is too small");
            }

            @Override
            public int compress(ByteBuffer src, int srcOff, int srcLen, ByteBuffer dest, int destOff, int maxDestLen) {
                return delegate.compress(src, srcOff, srcLen, dest, destOff, maxDestLen);
            }
        };
        Codec reference = Lz4FuzzSupport.javaCodecs().get(0);
        List<Codec> codecs = List.of(reference.withCompressor(broken));
        AssertionError error = assertThrows(AssertionError.class, () -> Lz4RoundTripTarget.run(codecs, config(9, false, 0, 0), Lz4BlockDecompressorTargetTest.DATA));
        assertTrue(error.getMessage().contains("maxCompressedLength"), error.getMessage());
    }

    private static Lz4RoundTripTarget.Config config(int level, boolean limitOutput, int maxDestLen, int flags) {
        return new Lz4RoundTripTarget.Config(
            level, flags * 1000, limitOutput, maxDestLen, flags % 4, 1 + flags % 3, flags % 5, 1 + flags % 2, flags % 7, flags % 3,
            BufferKind.fromBits(flags & 3, true),
            BufferKind.fromBits((flags >> 2) & 1, false),
            (flags & 0x10) != 0 ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN,
            (flags & 0x20) != 0 ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN
        );
    }
}

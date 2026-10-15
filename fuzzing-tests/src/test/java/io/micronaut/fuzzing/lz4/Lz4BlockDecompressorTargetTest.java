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
import net.jpountz.lz4.LZ4CompressorWithLength;
import net.jpountz.lz4.LZ4Exception;
import net.jpountz.lz4.LZ4Factory;
import net.jpountz.lz4.LZ4SafeDecompressor;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class Lz4BlockDecompressorTargetTest {
    static final byte[] DATA = "hello hello hello hello hello lz4 lz4 lz4 lz4 lz4 lz4".getBytes(UTF_8);
    static final byte[] COMPRESSED = LZ4Factory.safeInstance().fastCompressor().compress(DATA);

    @Test
    void usesNativeIfAvailable() {
        assertEquals(Lz4FuzzSupport.isNativeAvailable() ? 3 : 2, Lz4FuzzSupport.codecs().size());
        assumeTrue(Lz4FuzzSupport.isNativeAvailable(), "native lz4-java is not available on this platform");
        assertTrue(Lz4FuzzSupport.codecs().get(2).nativeCode());
    }

    @Test
    void fuzzesValidInput() {
        Lz4BlockDecompressorTarget.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            DATA.length, 3, 5, 7, 2, 1, 4, 0b11_0101, COMPRESSED
        )));
    }

    @Test
    void validInputWithAllBufferKindsAndLengths() {
        for (int flags = 0; flags < 64; flags++) {
            for (int maxDestLen : new int[] {0, DATA.length - 1, DATA.length, DATA.length + 100}) {
                Lz4BlockDecompressorTarget.run(Lz4FuzzSupport.codecs(), config(maxDestLen, flags), COMPRESSED);
            }
        }
    }

    @Test
    void invalidInputs() {
        byte[][] inputs = {
            new byte[0],
            {0},
            {0x10},
            {0x1F, 'a', 0, 0},
            {(byte) 0xF0, (byte) 0xFF, (byte) 0xFF},
            {0x11, 'a', 2, 0, 0x00},
            {0x40, 'a', 'b', 'c', 'd', 0, 0, 0x00},
            "garbage that is not lz4 at all".getBytes(UTF_8),
            java.util.Arrays.copyOf(COMPRESSED, COMPRESSED.length - 1),
            // match with offset 0 at the end of the input: accepted by the native implementation only
            java.util.HexFormat.of().parseHex("e4e4e4e4e4e4e4e4e4e49600004001000000"),
        };
        for (byte[] input : inputs) {
            for (int flags = 0; flags < 64; flags += 5) {
                Lz4BlockDecompressorTarget.run(Lz4FuzzSupport.codecs(), config(64, flags), input);
            }
        }
    }

    @Test
    void lengthPrefixedInput() {
        byte[] withLength = new LZ4CompressorWithLength(LZ4Factory.safeInstance().fastCompressor()).compress(DATA);
        Lz4BlockDecompressorTarget.run(Lz4FuzzSupport.codecs(), config(DATA.length, 0b01_0100), withLength);
        Lz4BlockDecompressorTarget.run(Lz4FuzzSupport.codecs(), config(DATA.length - 1, 0b10_0001), withLength);
        withLength[0]++; // declared length does not match
        Lz4BlockDecompressorTarget.run(Lz4FuzzSupport.codecs(), config(DATA.length + 1, 0), withLength);
        withLength[3] = (byte) 0x80; // negative declared length
        Lz4BlockDecompressorTarget.run(Lz4FuzzSupport.codecs(), config(DATA.length, 0), withLength);
    }

    @Test
    void withoutNative() {
        Lz4BlockDecompressorTarget.run(Lz4FuzzSupport.javaCodecs(), config(DATA.length, 0b11_0110), COMPRESSED);
        Lz4BlockDecompressorTarget.run(Lz4FuzzSupport.javaCodecs(), config(DATA.length, 0), new byte[] {1, 2, 3});
    }

    @Test
    void detectsWriteOutsideOfDestination() {
        LZ4SafeDecompressor delegate = LZ4Factory.safeInstance().safeDecompressor();
        LZ4SafeDecompressor broken = new LZ4SafeDecompressor() {
            @Override
            public int decompress(byte[] src, int srcOff, int srcLen, byte[] dest, int destOff, int maxDestLen) {
                int n = delegate.decompress(src, srcOff, srcLen, dest, destOff, maxDestLen);
                dest[destOff + maxDestLen] = 0x42;
                return n;
            }

            @Override
            public int decompress(ByteBuffer src, int srcOff, int srcLen, ByteBuffer dest, int destOff, int maxDestLen) {
                return delegate.decompress(src, srcOff, srcLen, dest, destOff, maxDestLen);
            }
        };
        AssertionError error = assertThrows(AssertionError.class, () -> Lz4BlockDecompressorTarget.run(withBrokenDecompressor(broken), config(DATA.length, 0), COMPRESSED));
        assertTrue(error.getMessage().contains("modified memory outside"), error.getMessage());
    }

    @Test
    void detectsWrongOutput() {
        LZ4SafeDecompressor delegate = LZ4Factory.safeInstance().safeDecompressor();
        LZ4SafeDecompressor broken = new LZ4SafeDecompressor() {
            @Override
            public int decompress(byte[] src, int srcOff, int srcLen, byte[] dest, int destOff, int maxDestLen) {
                return delegate.decompress(src, srcOff, srcLen, dest, destOff, maxDestLen);
            }

            @Override
            public int decompress(ByteBuffer src, int srcOff, int srcLen, ByteBuffer dest, int destOff, int maxDestLen) {
                int n = delegate.decompress(src, srcOff, srcLen, dest, destOff, maxDestLen);
                dest.put(destOff, (byte) (dest.get(destOff) + 1));
                return n;
            }
        };
        AssertionError error = assertThrows(AssertionError.class, () -> Lz4BlockDecompressorTarget.run(withBrokenDecompressor(broken), config(DATA.length, 0), COMPRESSED));
        assertTrue(error.getMessage().contains("decompress(ByteBuffer): reference"), error.getMessage());
    }

    @Test
    void comparesNativeBufferVariantWithNativeArrayVariant() {
        LZ4SafeDecompressor delegate = LZ4Factory.safeInstance().safeDecompressor();
        LZ4SafeDecompressor broken = new LZ4SafeDecompressor() {
            @Override
            public int decompress(byte[] src, int srcOff, int srcLen, byte[] dest, int destOff, int maxDestLen) {
                return delegate.decompress(src, srcOff, srcLen, dest, destOff, maxDestLen);
            }

            @Override
            public int decompress(ByteBuffer src, int srcOff, int srcLen, ByteBuffer dest, int destOff, int maxDestLen) {
                throw new LZ4Exception("buffer handling bug");
            }
        };
        Codec reference = Lz4FuzzSupport.javaCodecs().get(0);
        Codec fakeNative = new Codec("fake-native", true, broken, reference.fastCompressor(), reference.highCompressor(), reference.hashes(), null);
        // a failure of only the buffer variant is reported, although native may reject inputs that Java accepts
        AssertionError error = assertThrows(AssertionError.class, () -> Lz4BlockDecompressorTarget.run(List.of(reference, fakeNative), config(DATA.length, 0b0100), COMPRESSED));
        assertTrue(error.getMessage().contains("fake-native decompress(ByteBuffer)"), error.getMessage());
        // read-only sources fall back to Java and are compared with the Java reference
        assertThrows(AssertionError.class, () -> Lz4BlockDecompressorTarget.run(List.of(reference, fakeNative), config(DATA.length, 0b0010), COMPRESSED));
    }

    @Test
    void doesNotAcceptOtherExceptions() {
        LZ4SafeDecompressor broken = new LZ4SafeDecompressor() {
            @Override
            public int decompress(byte[] src, int srcOff, int srcLen, byte[] dest, int destOff, int maxDestLen) {
                throw new ArrayIndexOutOfBoundsException();
            }

            @Override
            public int decompress(ByteBuffer src, int srcOff, int srcLen, ByteBuffer dest, int destOff, int maxDestLen) {
                throw new ArrayIndexOutOfBoundsException();
            }
        };
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> Lz4BlockDecompressorTarget.run(withBrokenDecompressor(broken), config(DATA.length, 0), new byte[] {1, 2, 3}));
    }

    private static List<Codec> withBrokenDecompressor(LZ4SafeDecompressor broken) {
        Codec reference = Lz4FuzzSupport.javaCodecs().get(0);
        return List.of(reference, reference.withSafeDecompressor(broken));
    }

    static Lz4BlockDecompressorTarget.Config config(int maxDestLen, int flags) {
        return new Lz4BlockDecompressorTarget.Config(
            maxDestLen, flags % 4, 1 + flags % 3, flags % 5, 1 + flags % 2, flags % 7, flags % 3,
            BufferKind.fromBits(flags & 3, true),
            BufferKind.fromBits((flags >> 2) & 1, false),
            (flags & 0x10) != 0 ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN,
            (flags & 0x20) != 0 ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN
        );
    }
}

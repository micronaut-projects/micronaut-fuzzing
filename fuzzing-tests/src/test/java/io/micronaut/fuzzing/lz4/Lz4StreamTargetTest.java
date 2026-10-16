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
import io.micronaut.fuzzing.lz4.Lz4FuzzSupport.Codec;
import net.jpountz.lz4.LZ4BlockOutputStream;
import net.jpountz.lz4.LZ4Factory;
import net.jpountz.lz4.LZ4FrameOutputStream;
import net.jpountz.lz4.LZ4SafeDecompressor;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static io.micronaut.fuzzing.lz4.Lz4StreamTarget.FLAG_ACCEPT_OVERSIZED_BLOCKS;
import static io.micronaut.fuzzing.lz4.Lz4StreamTarget.FLAG_BLOCK_CHECKSUM;
import static io.micronaut.fuzzing.lz4.Lz4StreamTarget.FLAG_CONCATENATE;
import static io.micronaut.fuzzing.lz4.Lz4StreamTarget.FLAG_CONTENT_CHECKSUM;
import static io.micronaut.fuzzing.lz4.Lz4StreamTarget.FLAG_CONTENT_SIZE;
import static io.micronaut.fuzzing.lz4.Lz4StreamTarget.FLAG_QUERY_CONTENT_SIZE;
import static io.micronaut.fuzzing.lz4.Lz4StreamTarget.FLAG_READ_SINGLE_FRAME;
import static io.micronaut.fuzzing.lz4.Lz4StreamTarget.FLAG_SKIP;
import static io.micronaut.fuzzing.lz4.Lz4StreamTarget.FLAG_STOP_ON_EMPTY_BLOCK;
import static io.micronaut.fuzzing.lz4.Lz4StreamTarget.FRAME_BLOCK_SIZE_SHIFT;
import static io.micronaut.fuzzing.lz4.Lz4StreamTarget.MODE_BLOCK_DECODE;
import static io.micronaut.fuzzing.lz4.Lz4StreamTarget.MODE_BLOCK_ROUND_TRIP;
import static io.micronaut.fuzzing.lz4.Lz4StreamTarget.MODE_FRAME_DECODE;
import static io.micronaut.fuzzing.lz4.Lz4StreamTarget.MODE_FRAME_ROUND_TRIP;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Lz4StreamTargetTest {
    private static final byte[] DATA = Lz4BlockDecompressorTargetTest.DATA;
    private static final int[] CHUNKS = {0, 7, 100, 3};

    @Test
    void fuzzesInput() throws IOException {
        Lz4StreamTarget.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            MODE_BLOCK_DECODE, FLAG_STOP_ON_EMPTY_BLOCK, 64, 9, 0, 1, 2, 3, blockStream(DATA)
        )));
    }

    @Test
    void decodesValidBlockStreams() throws IOException {
        byte[] stream = blockStream(DATA);
        byte[] twice = concat(stream, stream);
        for (int flags = 0; flags < 32; flags++) {
            Lz4StreamTarget.run(Lz4FuzzSupport.codecs(), config(MODE_BLOCK_DECODE, flags), stream);
            Lz4StreamTarget.run(Lz4FuzzSupport.codecs(), config(MODE_BLOCK_DECODE, flags), twice);
        }
    }

    @Test
    void decodesInvalidBlockStreams() throws IOException {
        byte[] stream = blockStream(DATA);
        byte[] corrupt = stream.clone();
        corrupt[corrupt.length / 2]++;
        byte[] oversized = Arrays.copyOf("LZ4Block".getBytes(), 21);
        oversized[8] = 0x2F; // LZ4, level 15
        oversized[12] = 0x7F; // compressed length 2 GiB
        oversized[13] = 0x10;
        assertTrue(Lz4StreamTarget.hasOversizedBlock(oversized));
        assertFalse(Lz4StreamTarget.hasOversizedBlock(stream));
        byte[][] inputs = {new byte[0], "LZ4".getBytes(), Arrays.copyOf(stream, stream.length - 1), corrupt, oversized, "not lz4 at all, but long enough".getBytes()};
        for (byte[] input : inputs) {
            for (int flags = 0; flags < 32; flags++) {
                Lz4StreamTarget.run(Lz4FuzzSupport.codecs(), config(MODE_BLOCK_DECODE, flags | FLAG_ACCEPT_OVERSIZED_BLOCKS), input);
            }
        }
    }

    @Test
    void decodesValidFrames() throws IOException {
        byte[] stream = frameStream(DATA, LZ4FrameOutputStream.FLG.Bits.BLOCK_INDEPENDENCE, LZ4FrameOutputStream.FLG.Bits.CONTENT_CHECKSUM,
            LZ4FrameOutputStream.FLG.Bits.BLOCK_CHECKSUM, LZ4FrameOutputStream.FLG.Bits.CONTENT_SIZE);
        byte[] skippable = {0x50, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 1, 2, 3};
        for (int flags = 0; flags < 32; flags++) {
            Lz4StreamTarget.run(Lz4FuzzSupport.codecs(), config(MODE_FRAME_DECODE, flags), stream);
            Lz4StreamTarget.run(Lz4FuzzSupport.codecs(), config(MODE_FRAME_DECODE, flags), concat(skippable, concat(stream, stream)));
        }
    }

    @Test
    void decodesInvalidFrames() throws IOException {
        byte[] stream = frameStream(DATA, LZ4FrameOutputStream.FLG.Bits.BLOCK_INDEPENDENCE, LZ4FrameOutputStream.FLG.Bits.CONTENT_CHECKSUM);
        byte[] corrupt = stream.clone();
        corrupt[corrupt.length - 10]++;
        byte[][] inputs = {
            new byte[0],
            {0x04, 0x22, 0x4D, 0x18},
            {0x04, 0x22, 0x4D, 0x18, 0x00, 0x40, 0x00}, // invalid FLG
            {0x04, 0x22, 0x4D, 0x18, 0x60, 0x00, 0x00}, // invalid BD
            {0x04, 0x22, 0x4D, 0x18, 0x60, (byte) 0x80, 0x00}, // reserved BD bit
            Arrays.copyOf(stream, stream.length - 1),
            corrupt,
        };
        for (byte[] input : inputs) {
            for (int flags = 0; flags < 32; flags++) {
                Lz4StreamTarget.run(Lz4FuzzSupport.codecs(), config(MODE_FRAME_DECODE, flags), input);
            }
        }
    }

    @Test
    void roundTrips() {
        byte[] random = new byte[3000];
        new Random(0).nextBytes(random);
        for (byte[] data : List.of(new byte[0], new byte[] {1}, DATA, random)) {
            for (int flags = 0; flags < 1 << (FRAME_BLOCK_SIZE_SHIFT + 2); flags += 997) {
                Lz4StreamTarget.run(Lz4FuzzSupport.codecs(), config(MODE_BLOCK_ROUND_TRIP, flags), data);
                Lz4StreamTarget.run(Lz4FuzzSupport.codecs(), config(MODE_FRAME_ROUND_TRIP, flags), data);
            }
        }
        // large enough for a 1 MB frame block size
        byte[] large = new byte[300_000];
        new Random(1).nextBytes(large);
        Lz4StreamTarget.run(Lz4FuzzSupport.javaCodecs(), config(MODE_FRAME_ROUND_TRIP, 3 << FRAME_BLOCK_SIZE_SHIFT | FLAG_BLOCK_CHECKSUM), large);
        int all = FLAG_CONCATENATE | FLAG_CONTENT_CHECKSUM | FLAG_BLOCK_CHECKSUM | FLAG_CONTENT_SIZE | FLAG_QUERY_CONTENT_SIZE;
        Lz4StreamTarget.run(Lz4FuzzSupport.codecs(), config(MODE_FRAME_ROUND_TRIP, all), DATA);
        Lz4StreamTarget.run(Lz4FuzzSupport.codecs(), config(MODE_FRAME_ROUND_TRIP, all | FLAG_READ_SINGLE_FRAME), DATA);
    }

    @Test
    void withoutNative() throws IOException {
        Lz4StreamTarget.run(Lz4FuzzSupport.javaCodecs(), config(MODE_BLOCK_DECODE, FLAG_SKIP), blockStream(DATA));
        Lz4StreamTarget.run(Lz4FuzzSupport.javaCodecs(), config(MODE_FRAME_ROUND_TRIP, FLAG_CONTENT_CHECKSUM), DATA);
    }

    @Test
    void detectsWrongOutput() throws IOException {
        LZ4SafeDecompressor delegate = LZ4Factory.safeInstance().safeDecompressor();
        LZ4SafeDecompressor broken = new LZ4SafeDecompressor() {
            @Override
            public int decompress(byte[] src, int srcOff, int srcLen, byte[] dest, int destOff, int maxDestLen) {
                int n = delegate.decompress(src, srcOff, srcLen, dest, destOff, maxDestLen);
                dest[destOff]++;
                return n;
            }

            @Override
            public int decompress(ByteBuffer src, int srcOff, int srcLen, ByteBuffer dest, int destOff, int maxDestLen) {
                return delegate.decompress(src, srcOff, srcLen, dest, destOff, maxDestLen);
            }
        };
        Codec reference = Lz4FuzzSupport.javaCodecs().get(0);
        List<Codec> codecs = List.of(reference, reference.withSafeDecompressor(broken));
        // the frame format has no checksum by default, so the corruption is only visible in the output
        byte[] frame = frameStream(DATA, LZ4FrameOutputStream.FLG.Bits.BLOCK_INDEPENDENCE);
        AssertionError error = assertThrows(AssertionError.class, () -> Lz4StreamTarget.run(codecs, config(MODE_FRAME_DECODE, 0), frame));
        assertTrue(error.getMessage().contains("decoded"), error.getMessage());
        assertThrows(AssertionError.class, () -> Lz4StreamTarget.run(codecs, config(MODE_FRAME_ROUND_TRIP, 0), DATA));
    }

    @Test
    void rejectsUnexpectedWrappedExceptions() {
        Lz4StreamTarget.checkException(new IOException("Stream is corrupted", new net.jpountz.lz4.LZ4Exception("bad")), false);
        assertThrows(AssertionError.class, () -> Lz4StreamTarget.checkException(new IOException("Stream is corrupted", new ArrayIndexOutOfBoundsException()), false));
        assertThrows(AssertionError.class, () -> Lz4StreamTarget.checkException(new IOException("Stream is corrupted", new IllegalArgumentException()), true));
        // the descriptor validation exceptions are only accepted when thrown by the frame header parsing
        assertThrows(AssertionError.class, () -> Lz4StreamTarget.checkException(new IOException("Invalid or unsupported frame descriptor", new RuntimeException()), true));
    }

    private static Lz4StreamTarget.Config config(int mode, int flags) {
        return new Lz4StreamTarget.Config(mode, flags, 64 + flags % 200, flags % 19 - 1, CHUNKS);
    }

    private static byte[] blockStream(byte[] data) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (LZ4BlockOutputStream out = new LZ4BlockOutputStream(bytes, 64, LZ4Factory.safeInstance().fastCompressor())) {
            out.write(data);
        }
        return bytes.toByteArray();
    }

    private static byte[] frameStream(byte[] data, LZ4FrameOutputStream.FLG.Bits... bits) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (LZ4FrameOutputStream out = new LZ4FrameOutputStream(bytes, LZ4FrameOutputStream.BLOCKSIZE.SIZE_64KB, data.length, bits)) {
            out.write(data);
        }
        return bytes.toByteArray();
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}

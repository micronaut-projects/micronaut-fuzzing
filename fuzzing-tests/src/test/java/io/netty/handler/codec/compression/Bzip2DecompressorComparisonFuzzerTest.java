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
package io.netty.handler.codec.compression;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import io.netty.buffer.ByteBuf;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderException;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.List;

import static io.micronaut.fuzzing.EmbeddedChannelFuzzerBase.SEPARATOR;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertFalse;

class Bzip2DecompressorComparisonFuzzerTest {
    private static final byte[] PLAIN = "hello hello hello world, this is some text to compress. hello world!"
        .repeat(20).getBytes(UTF_8);

    @Test
    void valid() {
        byte[] compressed = compress(PLAIN);
        fuzz(1, compressed);
        fuzz(65536, compressed);
        // split into several chunks
        ByteArrayOutputStream split = new ByteArrayOutputStream();
        split.write(compressed, 0, 7);
        split.writeBytes(SEPARATOR.getBytes(UTF_8));
        split.write(compressed, 7, compressed.length - 7);
        fuzz(100, split.toByteArray());
    }

    @Test
    void corrupted() {
        byte[] compressed = compress(PLAIN);
        fuzz(1024, Arrays.copyOf(compressed, compressed.length - 3));
        byte[] crc = compressed.clone();
        crc[crc.length - 1] ^= 1;
        fuzz(1024, crc);
        byte[] magic = compressed.clone();
        magic[0] = 'X';
        fuzz(1024, magic);
    }

    @Test
    void invalidHuffmanCodeLength() {
        // lengths that the bzip2 format does not allow; on Netty versions without
        // https://github.com/netty/netty/pull/17812 these hit the known bug filter
        for (int length : new int[] {0, -1, 24, 27, 31}) {
            fuzz(1024, huffmanStream(length));
        }
        fuzz(1024, huffmanStream(23));
    }

    @Test
    void unrelatedExceptionsAreNotIgnored() {
        Bzip2DecompressorComparisonFuzzer fuzzer = new Bzip2DecompressorComparisonFuzzer();
        assertFalse(fuzzer.isExpectedLegacyException(new DecoderException(new ArrayIndexOutOfBoundsException())));
        assertFalse(fuzzer.isExpectedLegacyException(new DecoderException(new IllegalStateException())));
        assertFalse(fuzzer.isExpectedException(new ArrayIndexOutOfBoundsException()));
    }

    private static void fuzz(int size, byte[] input) {
        Bzip2DecompressorComparisonFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(size, input)));
    }

    private static byte[] compress(byte[] input) {
        EmbeddedChannel channel = new EmbeddedChannel(new Bzip2Encoder());
        channel.writeOutbound(channel.alloc().buffer().writeBytes(input));
        channel.finish();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteBuf buf;
        while ((buf = channel.readOutbound()) != null) {
            byte[] bytes = new byte[buf.readableBytes()];
            buf.readBytes(bytes);
            out.writeBytes(bytes);
            buf.release();
        }
        return out.toByteArray();
    }

    /**
     * Build a bzip2 stream whose first block has two Huffman tables for an alphabet of three symbols, where every
     * symbol has the given code length.
     */
    private static byte[] huffmanStream(int length) {
        BitWriter bits = new BitWriter();
        bits.write(0, 1); // not randomised
        bits.write(0, 24); // BWT start pointer
        bits.write(1, 16); // symbol map: first range in use
        bits.write(0x8000, 16); // symbol map: only the first byte value
        bits.write(2, 3); // Huffman groups
        bits.write(1, 15); // selectors
        bits.write(0, 1); // selector MTF 0
        for (int table = 0; table < 2; table++) {
            int start = Math.max(length, 1);
            bits.write(start, 5);
            for (int symbol = 0; symbol < 3; symbol++) {
                for (int i = length; i < start; i++) {
                    bits.write(0b11, 2); // decrement
                }
                bits.write(0, 1); // next symbol
            }
        }
        bits.write(0, 64);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[] {'B', 'Z', 'h', '1', 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0, 0, 0, 0});
        out.writeBytes(bits.toByteArray());
        return out.toByteArray();
    }

    private static final class BitWriter {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();
        private int current;
        private int count;

        void write(long value, int n) {
            for (int i = n - 1; i >= 0; i--) {
                current = current << 1 | (int) (value >>> i) & 1;
                if (++count == 8) {
                    out.write(current);
                    current = 0;
                    count = 0;
                }
            }
        }

        byte[] toByteArray() {
            while (count != 0) {
                write(0, 1);
            }
            return out.toByteArray();
        }
    }
}

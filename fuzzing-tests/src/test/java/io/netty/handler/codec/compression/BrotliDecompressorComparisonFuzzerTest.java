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

import com.aayushatharva.brotli4j.Brotli4jLoader;
import com.aayushatharva.brotli4j.encoder.Encoder;
import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import io.netty.buffer.ByteBufAllocator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static io.micronaut.fuzzing.EmbeddedChannelFuzzerBase.SEPARATOR;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class BrotliDecompressorComparisonFuzzerTest {
    private static final byte[] PLAIN = "hello hello hello world, this is some text to compress. hello world!"
        .repeat(20).getBytes(UTF_8);

    @BeforeAll
    static void loadNative() {
        Brotli4jLoader.ensureAvailability();
    }

    @Test
    void text() throws IOException {
        byte[] compressed = compress(PLAIN, 16);
        for (int size : new int[] {1, 7, 65536}) {
            AbstractDirectDecompressorFuzzer.Result result = new BrotliDecompressorComparisonFuzzer()
                .decompress(size, compressed, ByteBufAllocator.DEFAULT);
            assertFalse(result.failed());
            assertArrayEquals(PLAIN, result.output().bytes.toByteArray());
            fuzz(size, compressed);
            fuzz(size, split(compressed, 1, 5, compressed.length - 2));
        }
    }

    @Test
    void corrupted() throws IOException {
        byte[] compressed = compress(PLAIN, 16);
        fuzz(1024, Arrays.copyOf(compressed, compressed.length - 3));
        compressed[compressed.length / 2] ^= 0x55;
        fuzz(1024, compressed);
    }

    /**
     * Before <a href="https://github.com/netty/netty/pull/17870">netty/netty#17870</a>, the decoders truncated the
     * output of highly compressible data.
     */
    @Test
    void highlyCompressible() throws IOException {
        byte[] largePlain = new byte[524288];
        byte[] smallPlain = new byte[100000];
        byte[] large = compress(largePlain, 18);
        byte[] small = compress(smallPlain, 10);
        for (int size : new int[] {1000, 65536}) {
            BrotliDecompressorComparisonFuzzer fuzzer = new BrotliDecompressorComparisonFuzzer();
            assertArrayEquals(largePlain,
                fuzzer.decompress(size, large, ByteBufAllocator.DEFAULT).output().bytes.toByteArray());
            assertArrayEquals(smallPlain,
                fuzzer.decompress(size, small, ByteBufAllocator.DEFAULT).output().bytes.toByteArray());
            fuzz(size, large);
            fuzz(size, small);
            fuzz(size, split(small, 3));
        }
    }

    private static void fuzz(int size, byte[] input) {
        BrotliDecompressorComparisonFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(size, input)));
    }

    private static byte[] compress(byte[] input, int window) throws IOException {
        return Encoder.compress(input, new Encoder.Parameters().setWindow(window));
    }

    private static byte[] split(byte[] input, int... positions) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int start = 0;
        for (int position : positions) {
            out.write(input, start, position - start);
            out.writeBytes(SEPARATOR.getBytes(UTF_8));
            start = position;
        }
        out.write(input, start, input.length - start);
        return out.toByteArray();
    }
}

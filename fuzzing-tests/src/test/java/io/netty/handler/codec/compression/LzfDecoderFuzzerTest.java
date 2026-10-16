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
import com.ning.compress.lzf.LZFEncoder;
import com.ning.compress.lzf.LZFException;
import io.netty.handler.codec.DecoderException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayOutputStream;
import java.util.List;

import static io.micronaut.fuzzing.EmbeddedChannelFuzzerBase.SEPARATOR;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LzfDecoderFuzzerTest {
    private static final byte[] PLAIN = "hello hello hello world, this is some text to compress. hello world!"
        .repeat(20).getBytes(UTF_8);

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void validChunks(boolean safe) {
        byte[] compressed = LZFEncoder.encode(PLAIN);
        byte[] uncompressed = {'Z', 'V', 0, 0, 3, 'a', 'b', 'c'};
        fuzz(safe, concat(compressed, uncompressed));
        fuzz(safe, split(concat(compressed, uncompressed), 1, 6, compressed.length + 2));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void truncatedBlock(boolean safe) {
        // compressed chunk with a literal run of 6 bytes, but only 1 byte of input
        fuzz(safe, new byte[] {'Z', 'V', 1, 0, 2, 0, 10, 5, 'a'});
        // compressed chunk without content
        fuzz(safe, new byte[] {'Z', 'V', 1, 0, 0, 0, 0});
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void invalidBackReference(boolean safe) {
        // compressed chunk that starts with a back reference
        fuzz(safe, split(new byte[] {'Z', 'V', 1, 0, 2, 0, 3, 0x20, 0}, 4));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void retryOnSameInstance(boolean safe) {
        LzfDecoderFuzzer fuzzer = new LzfDecoderFuzzer(safe);
        fuzzer.test(CannedFuzzedDataProvider.create(List.of(LZFEncoder.encode(PLAIN))));
        fuzzer.test(CannedFuzzedDataProvider.create(List.of(LZFEncoder.encode(PLAIN))));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void otherExceptionsAreReported(boolean safe) {
        LzfDecoderFuzzer fuzzer = new LzfDecoderFuzzer(safe);
        assertFalse(LzfDecoderFuzzer.isCorruptChunk(new DecoderException(new LZFException("not from a decoder"))));
        assertThrows(DecoderException.class, () -> fuzzer.onException(new DecoderException(new LZFException("x"))));
        assertThrows(DecoderException.class, () -> fuzzer.onException(new DecoderException("x")));
    }

    private static void fuzz(boolean safe, byte[] input) {
        LzfDecoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(safe, input)));
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
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

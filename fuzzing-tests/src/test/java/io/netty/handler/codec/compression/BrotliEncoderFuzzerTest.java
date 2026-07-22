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
import org.junit.jupiter.api.Test;

import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;

class BrotliEncoderFuzzerTest {
    @Test
    void fuzzesSinglePayloadWithOptionsPrefix() {
        BrotliEncoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            new byte[] { 5, 18, 1, 'h', 'e', 'l', 'l', 'o' }
        )));
    }

    @Test
    void fuzzesSeparatedPayloadChunks() {
        BrotliEncoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            join(
                new byte[] { 9, 22, 0 },
                "hello".getBytes(UTF_8),
                "world".getBytes(UTF_8)
            )
        )));
    }

    private static byte[] join(byte[] options, byte[] firstChunk, byte[] secondChunk) {
        byte[] separator = "SEP".getBytes(UTF_8);
        byte[] result = new byte[options.length + separator.length + firstChunk.length
            + separator.length + secondChunk.length];
        int offset = 0;
        System.arraycopy(options, 0, result, offset, options.length);
        offset += options.length;
        System.arraycopy(separator, 0, result, offset, separator.length);
        offset += separator.length;
        System.arraycopy(firstChunk, 0, result, offset, firstChunk.length);
        offset += firstChunk.length;
        System.arraycopy(separator, 0, result, offset, separator.length);
        offset += separator.length;
        System.arraycopy(secondChunk, 0, result, offset, secondChunk.length);
        return result;
    }
}

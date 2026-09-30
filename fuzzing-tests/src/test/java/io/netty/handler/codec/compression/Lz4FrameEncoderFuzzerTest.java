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

import java.io.ByteArrayOutputStream;
import java.util.List;

import static io.micronaut.fuzzing.EmbeddedChannelFuzzerBase.SEPARATOR;
import static java.nio.charset.StandardCharsets.UTF_8;

class Lz4FrameEncoderFuzzerTest {
    @Test
    void fuzzesXxHashPayload() throws Exception {
        Lz4FrameEncoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            0,
            false,
            64,
            0,
            0,
            "hello".getBytes(UTF_8)
        )));
    }

    @Test
    void fuzzesAdlerPayloadChunks() throws Exception {
        Lz4FrameEncoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            1,
            true,
            256,
            1,
            chunks("hello".getBytes(UTF_8), "world".getBytes(UTF_8))
        )));
    }

    @Test
    void fuzzesCrcPayload() throws Exception {
        Lz4FrameEncoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            0,
            false,
            1024,
            2,
            "foobar".getBytes(UTF_8)
        )));
    }

    private static byte[] chunks(byte[] firstChunk, byte[] secondChunk) {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.writeBytes(firstChunk);
        result.writeBytes(SEPARATOR.getBytes(UTF_8));
        result.writeBytes(secondChunk);
        return result.toByteArray();
    }
}

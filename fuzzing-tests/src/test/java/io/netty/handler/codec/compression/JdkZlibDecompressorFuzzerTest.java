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
import java.util.zip.DeflaterOutputStream;

import static io.micronaut.fuzzing.EmbeddedChannelFuzzerBase.SEPARATOR;
import static java.nio.charset.StandardCharsets.UTF_8;

class JdkZlibDecompressorFuzzerTest {
    @Test
    void fuzzesDirectDecompressorWithFragmentedZlibInput() throws Exception {
        byte[] compressed = zlib("hello world".getBytes(UTF_8));
        JdkZlibDecompressorFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            1024,
            chunks(compressed, 3)
        )));
    }

    @Test
    void comparesDirectAndLegacyDecompressors() throws Exception {
        byte[] compressed = zlib("hello world".getBytes(UTF_8));
        JdkZlibDecompressorComparisonFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            1024,
            chunks(compressed, 3)
        )));
    }

    private static byte[] zlib(byte[] input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (DeflaterOutputStream deflater = new DeflaterOutputStream(output)) {
            deflater.write(input);
        }
        return output.toByteArray();
    }

    private static byte[] chunks(byte[] input, int splitAt) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(input, 0, splitAt);
        output.writeBytes(SEPARATOR.getBytes(UTF_8));
        output.write(input, splitAt, input.length - splitAt);
        return output.toByteArray();
    }
}

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
package net.jpountz.fuzz;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import net.jpountz.lz4.LZ4BlockOutputStream;
import net.jpountz.lz4.LZ4CompressorWithLength;
import net.jpountz.lz4.LZ4Factory;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;

class Lz4FuzzerTest {
    @Test
    void fuzzesXxHashWithValidAndInvalidRanges() {
        byte[] input = "hello lz4".getBytes(UTF_8);
        XXHashFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            input, 0, input.length, 123, 456L
        )));
        XXHashFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            input, -1, input.length, 123, 456L
        )));
    }

    @Test
    void fuzzesLengthPrefixedLz4Data() {
        byte[] compressed = new LZ4CompressorWithLength(LZ4Factory.fastestJavaInstance().fastCompressor())
            .compress("hello lz4".getBytes(UTF_8));
        LZ4DecompressorWithLengthFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(compressed)));
        LZ4DecompressorWithLengthFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            new byte[] {-1, -1, -1, 127}
        )));
    }

    @Test
    void fuzzesLz4BlockStreams() throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (LZ4BlockOutputStream output = new LZ4BlockOutputStream(bytes)) {
            output.write("hello lz4".getBytes(UTF_8));
        }
        LZ4BlockInputStreamFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(bytes.toByteArray())));
        LZ4BlockInputStreamFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            new byte[] {'L', 'Z', '4'}
        )));
    }
}

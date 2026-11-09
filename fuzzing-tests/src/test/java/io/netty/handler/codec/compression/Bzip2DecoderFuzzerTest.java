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
import io.netty.handler.codec.DecoderException;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.List;

import static io.micronaut.fuzzing.EmbeddedChannelFuzzerBase.SEPARATOR;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Bzip2DecoderFuzzerTest {
    private static final byte[] PLAIN = "hello hello hello world, this is some text to compress. hello world!"
        .repeat(20).getBytes(UTF_8);

    @Test
    void valid() {
        byte[] compressed = Bzip2DecompressorComparisonFuzzerTest.compress(PLAIN);
        fuzz(compressed);
        ByteArrayOutputStream split = new ByteArrayOutputStream();
        split.write(compressed, 0, 7);
        split.writeBytes(SEPARATOR.getBytes(UTF_8));
        split.write(compressed, 7, compressed.length - 7);
        fuzz(split.toByteArray());
    }

    @Test
    void corrupted() {
        byte[] compressed = Bzip2DecompressorComparisonFuzzerTest.compress(PLAIN);
        byte[] crc = compressed.clone();
        crc[crc.length - 1] ^= 1;
        fuzz(crc);
        byte[] magic = compressed.clone();
        magic[0] = 'X';
        fuzz(magic);
    }

    @Test
    void decodingAfterError() {
        // on Netty versions without https://github.com/netty/netty/pull/18259 this hits the known bug filter
        fuzz(Bzip2DecompressorComparisonFuzzerTest.tooFewSelectors());
    }

    @Test
    void inverseBwtAfterError() {
        // on Netty versions without https://github.com/netty/netty/pull/18259 this hits the known bug filter
        fuzz(Bzip2DecompressorComparisonFuzzerTest.endOfBlockAfterError());
    }

    @Test
    void retryOnSameInstance() {
        Bzip2DecoderFuzzer fuzzer = new Bzip2DecoderFuzzer();
        byte[] compressed = Bzip2DecompressorComparisonFuzzerTest.compress(PLAIN);
        fuzzer.test(CannedFuzzedDataProvider.create(List.of(compressed)));
        fuzzer.test(CannedFuzzedDataProvider.create(List.of(compressed)));
    }

    @Test
    void unrelatedExceptionsAreReported() {
        Bzip2DecoderFuzzer fuzzer = new Bzip2DecoderFuzzer();
        assertThrows(DecoderException.class,
            () -> fuzzer.onException(new DecoderException(new ArrayIndexOutOfBoundsException())));
        assertThrows(DecoderException.class,
            () -> fuzzer.onException(new DecoderException(new IndexOutOfBoundsException())));
    }

    private static void fuzz(byte[] input) {
        Bzip2DecoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(input)));
    }
}

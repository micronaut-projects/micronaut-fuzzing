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
package io.netty.handler.codec.redis;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import io.netty.handler.codec.DecoderException;
import org.junit.jupiter.api.Test;

import java.util.List;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RedisDecoderFuzzerTest {
    @Test
    void decodesSplitRespMessages() {
        RedisDecoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            1024,
            false,
            "+OK\r\n-ERR error\r\n:42\r\n$5\r\nhelSEPlo\r\n$-1\r\n*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n".getBytes(US_ASCII)
        )));
    }

    @Test
    void decodesInlineCommands() {
        RedisDecoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            1024,
            true,
            "PING\r\nSET key value\r\n".getBytes(US_ASCII)
        )));
    }

    @Test
    void ignoresMalformedInputAsExpectedNettyValidation() {
        RedisDecoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            1024,
            false,
            "PING\r\n".getBytes(US_ASCII)
        )));
    }

    @Test
    void ignoresTooLongInlineMessage() {
        RedisDecoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            1,
            true,
            "+OKOKOK".getBytes(US_ASCII)
        )));
    }

    @Test
    void ignoresKnownLineFeedWithoutCarriageReturnBug() {
        RedisDecoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            1024,
            false,
            "+\nab".getBytes(US_ASCII)
        )));
    }

    @Test
    void reportsWrappedUnexpectedExceptions() {
        RedisDecoderFuzzer fuzzer = new RedisDecoderFuzzer(CannedFuzzedDataProvider.create(List.of(1024, false)));
        assertThrows(NullPointerException.class, () -> fuzzer.onException(new NullPointerException()));
        assertThrows(DecoderException.class, () -> fuzzer.onException(
            new DecoderException(new RedisCodecException(new IndexOutOfBoundsException()))));
    }
}

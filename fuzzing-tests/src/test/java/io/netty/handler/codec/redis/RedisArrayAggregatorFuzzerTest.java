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
import io.netty.handler.codec.CodecException;
import io.netty.handler.codec.DecoderException;
import org.junit.jupiter.api.Test;

import java.util.List;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RedisArrayAggregatorFuzzerTest {
    private static RedisArrayAggregatorFuzzer run(int maxElements, int maxNestedArrayDepth, boolean inline,
                                                  String input) {
        RedisArrayAggregatorFuzzer fuzzer = new RedisArrayAggregatorFuzzer(CannedFuzzedDataProvider.create(List.of(
            1024, inline, maxElements, maxNestedArrayDepth)));
        fuzzer.test(CannedFuzzedDataProvider.create(List.of(input.getBytes(US_ASCII))));
        return fuzzer;
    }

    @Test
    void aggregatesNestedArraysAndFragmentedBulkStrings() {
        RedisArrayAggregatorFuzzer fuzzer = run(100, 10, false,
            "*3\r\n*2\r\n$5\r\nhelSEPlo\r\n:-42\r\n*-1\r\n$-1\r\nSEP*2\r\n*0\r\n$0\r\n\r\n+OK\r\n-ERR x\r\n");
        // the two top-level arrays, the ok and the error message
        assertEquals(4, fuzzer.roundTrips);
        assertEquals(List.of(), fuzzer.ignoredExceptions);
    }

    @Test
    void aggregatesInlineCommands() {
        RedisArrayAggregatorFuzzer fuzzer = run(100, 10, true, "*1\r\n+a\r\nPING\r\n\r\n\r\n");
        assertEquals(4, fuzzer.roundTrips);
    }

    @Test
    void skipsRoundTripForCarriageReturnInSimpleString() {
        RedisArrayAggregatorFuzzer fuzzer = run(100, 10, false, "*1\r\n+a\rb\r\n+ok\r\n");
        assertEquals(1, fuzzer.roundTrips);
    }

    @Test
    void ignoresTooManyElements() {
        RedisArrayAggregatorFuzzer fuzzer = run(2, 10, false, "*3\r\n:1\r\n:2\r\n:3\r\n");
        assertEquals(List.of("aggregator"), fuzzer.ignoredExceptions);
        // the elements of the rejected array arrive on their own
        assertEquals(3, fuzzer.roundTrips);
    }

    @Test
    void ignoresTooManyOutstandingElements() {
        RedisArrayAggregatorFuzzer fuzzer = run(3, 10, false, "*2\r\n*2\r\n:1\r\n:2\r\n:3\r\n");
        assertEquals(List.of("aggregator"), fuzzer.ignoredExceptions);
        assertEquals(3, fuzzer.roundTrips);
    }

    @Test
    void ignoresTooDeepNesting() {
        RedisArrayAggregatorFuzzer fuzzer = run(100, 1, false, "*1\r\n*1\r\n:1\r\n");
        assertEquals(List.of("aggregator"), fuzzer.ignoredExceptions);
        assertEquals(1, fuzzer.roundTrips);
    }

    @Test
    void ignoresIncompleteAggregateAtClose() {
        RedisArrayAggregatorFuzzer fuzzer = run(100, 10, false, "*2\r\n*2\r\n:1\r\n$5\r\nhe");
        // from both aggregators
        assertEquals(List.of("premature closure", "premature closure"), fuzzer.ignoredExceptions);
        assertEquals(0, fuzzer.roundTrips);
    }

    @Test
    void ignoresDecoderErrorInsideAggregate() {
        RedisArrayAggregatorFuzzer fuzzer = run(100, 10, false, "*2\r\n$3\r\nabc\r\nPING\r\n");
        assertEquals(List.of("decoder", "premature closure"), fuzzer.ignoredExceptions);
        assertEquals(0, fuzzer.roundTrips);
    }

    @Test
    void ignoresKnownLineFeedWithoutCarriageReturnBug() {
        RedisArrayAggregatorFuzzer fuzzer = run(100, 10, false, "*2\r\n+\nab");
        assertEquals(List.of("decoder", "premature closure"), fuzzer.ignoredExceptions);
    }

    @Test
    void canRetryWithFreshHandlers() {
        RedisArrayAggregatorFuzzer fuzzer = new RedisArrayAggregatorFuzzer(CannedFuzzedDataProvider.create(List.of(
            1024, false, 100, 10)));
        byte[] input = "*2\r\n:1\r\n:2\r\n".getBytes(US_ASCII);
        fuzzer.test(CannedFuzzedDataProvider.create(List.of(input)));
        assertEquals(1, fuzzer.roundTrips);
        fuzzer.test(CannedFuzzedDataProvider.create(List.of(input)));
        assertEquals(1, fuzzer.roundTrips);
    }

    @Test
    void oracleDetectsDifferentMessages() {
        RedisMessage a = new ArrayRedisMessage(List.of(new IntegerRedisMessage(1), new SimpleStringRedisMessage("a")));
        RedisMessage b = new ArrayRedisMessage(List.of(new IntegerRedisMessage(1), new SimpleStringRedisMessage("b")));
        RedisArrayAggregatorFuzzer.assertSameMessage(a, a);
        RedisArrayAggregatorFuzzer.assertSameMessage(ArrayRedisMessage.EMPTY_INSTANCE, new ArrayRedisMessage(List.of()));
        assertThrows(AssertionError.class, () -> RedisArrayAggregatorFuzzer.assertSameMessage(a, b));
        assertThrows(AssertionError.class, () -> RedisArrayAggregatorFuzzer.assertSameMessage(
            ArrayRedisMessage.NULL_INSTANCE, ArrayRedisMessage.EMPTY_INSTANCE));
    }

    @Test
    void reportsUnexpectedExceptions() {
        RedisArrayAggregatorFuzzer fuzzer = new RedisArrayAggregatorFuzzer(CannedFuzzedDataProvider.create(List.of(
            1024, false, 100, 10)));
        assertThrows(DecoderException.class, () -> fuzzer.onException(
            new DecoderException(new IllegalStateException())));
        // a cause-less CodecException that RedisArrayAggregator did not throw
        assertThrows(DecoderException.class, () -> fuzzer.onException(new DecoderException(new CodecException("x"))));
        assertThrows(DecoderException.class, () -> fuzzer.onException(
            new DecoderException(new RedisCodecException(new IndexOutOfBoundsException()))));
    }
}

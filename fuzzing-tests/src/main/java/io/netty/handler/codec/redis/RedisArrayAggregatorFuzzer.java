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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.FlagAppender;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.CodecException;
import io.netty.util.LeakPresenceDetector;
import io.netty.util.ReferenceCountUtil;

/**
 * Fuzzes aggregation of fragmented and nested Redis array messages.
 */
@FuzzTarget
@Dict({"PING", "SET", "GET"})
public final class RedisArrayAggregatorFuzzer {
    private static final int MAX_MESSAGES = 128;
    private static final int MAX_STRING_LENGTH = 64;

    private RedisArrayAggregatorFuzzer() {
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        int maxElements = fuzzedDataProvider.consumeInt(1, 64);
        int maxNestedArrayDepth = fuzzedDataProvider.consumeInt(1, 16);
        EmbeddedChannel channel = new EmbeddedChannel(new RedisArrayAggregator(maxElements, maxNestedArrayDepth));
        try {
            for (int i = 0; i < MAX_MESSAGES && fuzzedDataProvider.remainingBytes() > 0; i++) {
                channel.writeInbound(nextMessage(fuzzedDataProvider));
                releaseInbound(channel);
            }
        } catch (CodecException ignored) {
            // Invalid lengths and excessive nesting are expected for random input.
        } finally {
            try {
                channel.finish();
            } catch (CodecException ignored) {
                // Random input may end with an incomplete array or invalid aggregation state.
            }
            channel.finishAndReleaseAll();
        }
        LeakPresenceDetector.check();
        FlagAppender.checkTriggered();
    }

    private static RedisMessage nextMessage(FuzzedDataProvider fuzzedDataProvider) {
        return switch (fuzzedDataProvider.consumeInt(0, 8)) {
            case 0 -> new ArrayHeaderRedisMessage(fuzzedDataProvider.consumeLong());
            case 1 -> new SimpleStringRedisMessage(fuzzedDataProvider.consumeString(MAX_STRING_LENGTH));
            case 2 -> new ErrorRedisMessage(fuzzedDataProvider.consumeString(MAX_STRING_LENGTH));
            case 3 -> new IntegerRedisMessage(fuzzedDataProvider.consumeLong());
            case 4 -> new FullBulkStringRedisMessage(Unpooled.wrappedBuffer(
                fuzzedDataProvider.consumeBytes(MAX_STRING_LENGTH)));
            case 5 -> new BulkStringHeaderRedisMessage(fuzzedDataProvider.consumeInt(-1, MAX_STRING_LENGTH));
            case 6 -> ArrayRedisMessage.NULL_INSTANCE;
            case 7 -> ArrayRedisMessage.EMPTY_INSTANCE;
            default -> FullBulkStringRedisMessage.NULL_INSTANCE;
        };
    }

    private static void releaseInbound(EmbeddedChannel channel) {
        while (true) {
            Object message = channel.readInbound();
            if (message == null) {
                return;
            }
            ReferenceCountUtil.release(message);
        }
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(RedisArrayAggregatorFuzzer.class).fuzz();
    }
}

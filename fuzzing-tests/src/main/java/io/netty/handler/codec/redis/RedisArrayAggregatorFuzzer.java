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
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.CodecException;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.PrematureChannelClosureException;
import io.netty.util.ReferenceCountUtil;

import java.util.List;

/**
 * Fuzzes {@link RedisArrayAggregator} with the output of {@link RedisDecoder} and
 * {@link RedisBulkStringAggregator}, so that it sees nested arrays and fragmented bulk strings as they arrive from
 * the network. Every aggregated message is checked against the configured limits, and re-encoded with
 * {@link RedisEncoder} and decoded again, which must yield the same message.
 */
@FuzzTarget
@Dict({
    "SEP", "\r\n", "*", "$", "+", "-", ":", "*-1\r\n", "$-1\r\n", "*0\r\n", "$0\r\n\r\n", "*1\r\n", "*2\r\n",
    "*3\r\n", "*1\r\n*1\r\n", "*2\r\n*1\r\n", "$1\r\n", "$5\r\n", "$5\r\nhello\r\n", "+OK\r\n", "-ERR error\r\n",
    ":1\r\n", ":-1\r\n", "*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n", "PING\r\n"
})
public class RedisArrayAggregatorFuzzer extends HandlerFuzzerBase {
    private static final int MAX_INLINE_MESSAGE_LENGTH = 65536;
    private static final int MAX_ELEMENTS = 65536;
    private static final int MAX_NESTED_ARRAY_DEPTH = 1024;

    /**
     * Number of aggregated messages that passed the round trip check, for the smoke tests.
     */
    int roundTrips;

    private final int maxInlineMessageLength;
    private final boolean decodeInlineCommands;
    private final int maxElements;
    private final int maxNestedArrayDepth;

    public RedisArrayAggregatorFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        maxInlineMessageLength = fuzzedDataProvider.consumeInt(1, MAX_INLINE_MESSAGE_LENGTH);
        decodeInlineCommands = fuzzedDataProvider.consumeBoolean();
        maxElements = fuzzedDataProvider.consumeInt(1, MAX_ELEMENTS);
        maxNestedArrayDepth = fuzzedDataProvider.consumeInt(1, MAX_NESTED_ARRAY_DEPTH);
    }

    @Override
    protected EmbeddedChannel setUp() {
        return new EmbeddedChannel(
            new RedisDecoder(maxInlineMessageLength, FixedRedisMessagePool.INSTANCE, decodeInlineCommands),
            new RedisBulkStringAggregator(),
            new RedisArrayAggregator(maxElements, maxNestedArrayDepth),
            new ChannelInboundHandlerAdapter() {
                @Override
                public void channelRead(ChannelHandlerContext ctx, Object msg) {
                    try {
                        verify((RedisMessage) msg);
                    } catch (Throwable t) {
                        ReferenceCountUtil.release(msg);
                        throw t;
                    }
                    ctx.fireChannelRead(msg);
                }
            }
        );
    }

    private void verify(RedisMessage msg) {
        checkLimits(msg, 0, 0);
        if (isEncodable(msg)) {
            try {
                roundTrip(msg);
            } catch (Exception e) {
                // don't let onException filter a validation exception of the second decode
                throw new AssertionError("Round trip failed for " + msg, e);
            }
            roundTrips++;
        }
    }

    /**
     * Check that the aggregate is complete and within the configured limits. A non-empty array counts towards the
     * nesting depth, and the lengths of all non-empty arrays on the path from the root count towards maxElements,
     * because the aggregator bounds the sum of the lengths of all incomplete arrays.
     */
    private void checkLimits(RedisMessage msg, int depth, long pendingElements) {
        if (msg instanceof ArrayRedisMessage array) {
            List<RedisMessage> children = array.children();
            if (array.isNull() || children.isEmpty()) {
                return;
            }
            int childDepth = depth + 1;
            long childPending = pendingElements + children.size();
            if (childDepth > maxNestedArrayDepth || childPending > maxElements) {
                throw new AssertionError("Aggregated array exceeds limits: depth=" + childDepth + " pending="
                    + childPending + " maxNestedArrayDepth=" + maxNestedArrayDepth + " maxElements=" + maxElements);
            }
            for (RedisMessage child : children) {
                checkLimits(child, childDepth, childPending);
            }
        } else if (!(msg instanceof FullBulkStringRedisMessage
            || msg instanceof AbstractStringRedisMessage
            || msg instanceof IntegerRedisMessage)) {
            throw new AssertionError("Unexpected message after aggregation: " + msg);
        }
    }

    /**
     * RedisDecoder accepts a CR inside a simple string, error or inline command, but RedisEncoder rejects it.
     */
    private static boolean isEncodable(RedisMessage msg) {
        if (msg instanceof ArrayRedisMessage array) {
            for (RedisMessage child : array.children()) {
                if (!isEncodable(child)) {
                    return false;
                }
            }
            return true;
        } else if (msg instanceof AbstractStringRedisMessage s) {
            return s.content().indexOf('\r') == -1 && s.content().indexOf('\n') == -1;
        } else {
            return true;
        }
    }

    private void roundTrip(RedisMessage msg) {
        EmbeddedChannel encoder = new EmbeddedChannel(new RedisEncoder());
        ByteBuf encoded = ByteBufAllocator.DEFAULT.buffer();
        try {
            encoder.writeOutbound(ReferenceCountUtil.retain(msg));
            for (ByteBuf part; (part = encoder.readOutbound()) != null; ) {
                // RedisEncoder passes on the content of bulk strings, which is still part of msg. Don't consume it.
                encoded.writeBytes(part, part.readerIndex(), part.readableBytes());
                part.release();
            }
        } catch (Throwable t) {
            encoded.release();
            throw t;
        } finally {
            encoder.finishAndReleaseAll();
        }

        // The limits are the same as for the original input: an aggregate that passed them once must pass them
        // again. Re-encoding can make a simple string longer (invalid UTF-8 becomes U+FFFD), so don't limit
        // the line length.
        EmbeddedChannel decoder = new EmbeddedChannel(
            new RedisDecoder(RedisConstants.REDIS_MESSAGE_MAX_LENGTH, FixedRedisMessagePool.INSTANCE, decodeInlineCommands),
            new RedisBulkStringAggregator(),
            new RedisArrayAggregator(maxElements, maxNestedArrayDepth)
        );
        try {
            String hex = ByteBufUtil.hexDump(encoded);
            decoder.writeInbound(encoded);
            decoder.checkException();
            RedisMessage decoded = decoder.readInbound();
            try {
                if (decoded == null) {
                    throw new AssertionError("Re-encoded message did not decode: " + msg + " encoded=" + hex);
                }
                assertSameMessage(msg, decoded);
                if (decoder.inboundMessages().size() != 0) {
                    throw new AssertionError("Re-encoded message decoded to multiple messages: " + msg
                        + " encoded=" + hex);
                }
            } finally {
                ReferenceCountUtil.release(decoded);
            }
        } finally {
            decoder.finishAndReleaseAll();
        }
    }

    static void assertSameMessage(RedisMessage expected, RedisMessage actual) {
        if (!isSameMessage(expected, actual)) {
            throw new AssertionError("Round trip changed the message: expected=" + describe(expected)
                + " actual=" + describe(actual));
        }
    }

    private static String describe(RedisMessage msg) {
        if (msg instanceof ArrayRedisMessage array) {
            if (array.isNull()) {
                return "*null";
            }
            StringBuilder builder = new StringBuilder("[");
            for (RedisMessage child : array.children()) {
                if (builder.length() > 1) {
                    builder.append(", ");
                }
                builder.append(describe(child));
            }
            return builder.append(']').toString();
        } else if (msg instanceof FullBulkStringRedisMessage bulk) {
            return bulk.isNull() ? "$null" : "$" + ByteBufUtil.hexDump(bulk.content());
        } else {
            return msg.getClass().getSimpleName() + ":" + msg;
        }
    }

    private static boolean isSameMessage(RedisMessage expected, RedisMessage actual) {
        if (expected.getClass() != actual.getClass() && !isSameSingletonType(expected, actual)) {
            return false;
        }
        if (expected instanceof ArrayRedisMessage e) {
            ArrayRedisMessage a = (ArrayRedisMessage) actual;
            if (e.isNull() != a.isNull() || e.children().size() != a.children().size()) {
                return false;
            }
            for (int i = 0; i < e.children().size(); i++) {
                if (!isSameMessage(e.children().get(i), a.children().get(i))) {
                    return false;
                }
            }
            return true;
        } else if (expected instanceof FullBulkStringRedisMessage e) {
            FullBulkStringRedisMessage a = (FullBulkStringRedisMessage) actual;
            return e.isNull() == a.isNull() && ByteBufUtil.equals(e.content(), a.content());
        } else if (expected instanceof AbstractStringRedisMessage e) {
            return e.content().equals(((AbstractStringRedisMessage) actual).content());
        } else if (expected instanceof IntegerRedisMessage e) {
            return e.value() == ((IntegerRedisMessage) actual).value();
        } else {
            return false;
        }
    }

    /**
     * The NULL and EMPTY instances of the array and bulk string messages are anonymous subclasses.
     */
    private static boolean isSameSingletonType(RedisMessage expected, RedisMessage actual) {
        return expected instanceof ArrayRedisMessage && actual instanceof ArrayRedisMessage
            || expected instanceof FullBulkStringRedisMessage && actual instanceof FullBulkStringRedisMessage;
    }

    @Override
    protected void onException(Exception e) {
        Throwable t = e instanceof DecoderException && e.getCause() instanceof CodecException ? e.getCause() : e;
        // Validation failures of RedisDecoder (see RedisDecoderFuzzer). Unexpected exceptions have a cause.
        if (t instanceof RedisCodecException
            && (t.getCause() == null || RedisDecoderFuzzer.isKnownLineFeedBug(t.getCause()))) {
            return;
        }
        // Validation failures of RedisArrayAggregator: array too long, nested too deep, or too many outstanding
        // elements. MessageToMessageDecoder wraps them in a DecoderException.
        if (t != e && t.getClass() == CodecException.class && t.getCause() == null
            && isThrownBy(t, RedisArrayAggregator.class, "clearAndCreateException")) {
            return;
        }
        // Either aggregator fires this on channel close while an aggregate is incomplete.
        if (e.getClass() == PrematureChannelClosureException.class && e.getCause() == null) {
            return;
        }
        super.onException(e);
    }

    private static boolean isThrownBy(Throwable t, Class<?> type, String method) {
        for (StackTraceElement element : t.getStackTrace()) {
            if (element.getClassName().equals(type.getName())) {
                return element.getMethodName().equals(method);
            }
        }
        return false;
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        var fuzzer = new RedisArrayAggregatorFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(RedisArrayAggregatorFuzzer.class).fuzz();
    }
}

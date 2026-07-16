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
package io.netty.handler.codec.http.websocketx;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.micronaut.fuzzing.util.ByteSplitter;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.MessageAggregationException;
import io.netty.handler.codec.PrematureChannelClosureException;
import io.netty.handler.codec.TooLongFrameException;
import io.netty.util.LeakPresenceDetector;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.FastThreadLocalThread;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@Dict({
    "SEP", "text", "binary", "continuation", "ping", "pong", "close"
})
public class WebSocketFrameAggregatorFuzzer {
    private static final String SEPARATOR = "SEP";
    private static final ByteSplitter SPLITTER = ByteSplitter.create(SEPARATOR);
    private static final int MAX_CONTENT_LENGTH = 1024;
    private static final int MAX_FRAME_COUNT = 64;
    private static final int MAX_DATA_FRAME_BYTES = 512;
    private static final int MAX_CONTROL_FRAME_BYTES = 125;

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        FastThreadLocalThread.runWithFastThreadLocal(() -> test0(fuzzedDataProvider));
    }

    private static void test0(FuzzedDataProvider fuzzedDataProvider) {
        EmbeddedChannel channel = new EmbeddedChannel(
            new WebSocketFrameAggregator(fuzzedDataProvider.consumeInt(0, MAX_CONTENT_LENGTH)),
            new ReleaseAndIgnoreExpectedExceptionsHandler()
        );
        byte[] allBytes = fuzzedDataProvider.consumeRemainingAsBytes();
        ByteSplitter.ChunkIterator itr = SPLITTER.splitIterator(allBytes);
        try {
            for (int i = 0; i < MAX_FRAME_COUNT && channel.isOpen() && itr.hasNext(); i++) {
                itr.proceed();
                channel.writeInbound(nextFrame(channel, allBytes, itr.start(), itr.length()));
            }
        } finally {
            channel.finishAndReleaseAll();
        }
        LeakPresenceDetector.check();
    }

    private static WebSocketFrame nextFrame(EmbeddedChannel channel, byte[] frameBytes, int offset, int length) {
        int descriptor = length == 0 ? 0 : frameBytes[offset] & 0xff;
        boolean finalFragment = (descriptor & 1) != 0;
        int rsv = descriptor >> 1 & 7;
        int payloadOffset = offset + Math.min(1, length);
        int payloadLength = offset + length - payloadOffset;

        return switch ((descriptor >> 4) % 6) {
            case 0 -> new TextWebSocketFrame(
                finalFragment, rsv, nextPayload(channel, frameBytes, payloadOffset, payloadLength, MAX_DATA_FRAME_BYTES)
            );
            case 1 -> new BinaryWebSocketFrame(
                finalFragment, rsv, nextPayload(channel, frameBytes, payloadOffset, payloadLength, MAX_DATA_FRAME_BYTES)
            );
            case 2 -> new ContinuationWebSocketFrame(
                finalFragment, rsv, nextPayload(channel, frameBytes, payloadOffset, payloadLength, MAX_DATA_FRAME_BYTES)
            );
            case 3 -> new PingWebSocketFrame(
                finalFragment, rsv, nextPayload(channel, frameBytes, payloadOffset, payloadLength, MAX_CONTROL_FRAME_BYTES)
            );
            case 4 -> new PongWebSocketFrame(
                finalFragment, rsv, nextPayload(channel, frameBytes, payloadOffset, payloadLength, MAX_CONTROL_FRAME_BYTES)
            );
            case 5 -> new CloseWebSocketFrame(
                finalFragment, rsv, nextPayload(channel, frameBytes, payloadOffset, payloadLength, MAX_CONTROL_FRAME_BYTES)
            );
            default -> throw new IllegalStateException("Unexpected frame type");
        };
    }

    private static ByteBuf nextPayload(EmbeddedChannel channel, byte[] frameBytes, int offset, int payloadLength, int maxLength) {
        int length = Math.min(maxLength, payloadLength);
        ByteBuf payload = channel.alloc().buffer(length);
        payload.writeBytes(frameBytes, offset, length);
        return payload;
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(WebSocketFrameAggregatorFuzzer.class).fuzz();
    }

    private static final class ReleaseAndIgnoreExpectedExceptionsHandler extends ChannelInboundHandlerAdapter {
        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            ReferenceCountUtil.release(msg);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            if (cause instanceof MessageAggregationException
                || cause instanceof PrematureChannelClosureException
                || cause instanceof TooLongFrameException) {
                ctx.close();
                return;
            }
            super.exceptionCaught(ctx, cause);
        }
    }
}

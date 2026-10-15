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
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.MessageAggregationException;
import io.netty.handler.codec.PrematureChannelClosureException;
import io.netty.handler.codec.TooLongFrameException;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@Dict({
    "text", "binary", "continuation", "ping", "pong", "close",
    "\u0000\u0000", "\u0001\u0000", "\u0002\u0000", "\b\u0000", "\t\u0000", "\n\u0000",
    "\u0001\u007e", "\u0002\u007e"
})
public final class WebSocketFrameAggregatorFuzzer extends HandlerFuzzerBase {
    private static final int MAX_CONTENT_LENGTH = 1024;
    private static final int MAX_FRAME_PAYLOAD_LENGTH = 1024;

    private final int maxContentLength;

    private WebSocketFrameAggregatorFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        maxContentLength = fuzzedDataProvider.consumeInt(0, MAX_CONTENT_LENGTH);
    }

    @Override
    protected EmbeddedChannel setUp() {
        return new EmbeddedChannel(
            new WebSocket08FrameDecoder(false, true, MAX_FRAME_PAYLOAD_LENGTH, true),
            new WebSocketFrameAggregator(maxContentLength)
        );
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof CorruptedFrameException
            || e instanceof MessageAggregationException
            || e instanceof PrematureChannelClosureException
            || e instanceof TooLongFrameException) {
            return;
        }
        super.onException(e);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws Exception {
        new WebSocketFrameAggregatorFuzzer(fuzzedDataProvider).test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(WebSocketFrameAggregatorFuzzer.class).fuzz();
    }
}

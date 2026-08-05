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
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.PrematureChannelClosureException;
import io.netty.handler.codec.TooLongFrameException;

import javax.net.ssl.SSLException;
import java.nio.channels.ClosedChannelException;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@Dict({
    "SEP", "websocket", "hello", "foobar", "ping", "pong", "close"
})
public class WebSocket08FrameDecoderFuzzer extends HandlerFuzzerBase {
    private static final int MAX_FRAME_PAYLOAD_LENGTH = 65536;

    public WebSocket08FrameDecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(new WebSocket08FrameDecoder(nextConfig(fuzzedDataProvider)));
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof CorruptedFrameException
            || e instanceof TooLongFrameException
            || e instanceof PrematureChannelClosureException
            || e instanceof ClosedChannelException
            || e instanceof DecoderException && e.getCause() instanceof CorruptedFrameException) {
            return;
        }
        super.onException(e);
    }

    private static WebSocketDecoderConfig nextConfig(FuzzedDataProvider fuzzedDataProvider) {
        return WebSocketDecoderConfig.newBuilder()
            .expectMaskedFrames(fuzzedDataProvider.consumeBoolean())
            .allowExtensions(fuzzedDataProvider.consumeBoolean())
            .allowMaskMismatch(fuzzedDataProvider.consumeBoolean())
            .closeOnProtocolViolation(fuzzedDataProvider.consumeBoolean())
            .withUTF8Validator(fuzzedDataProvider.consumeBoolean())
            .maxFramePayloadLength(fuzzedDataProvider.consumeInt(1, MAX_FRAME_PAYLOAD_LENGTH))
            .build();
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new WebSocket08FrameDecoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(WebSocket08FrameDecoderFuzzer.class).fuzz();
    }
}

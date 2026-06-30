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
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.PrematureChannelClosureException;
import io.netty.handler.codec.TooLongFrameException;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpObjectAggregator;

import java.nio.channels.ClosedChannelException;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
public class WebSocketClientProtocolHandlerFuzzer extends HandlerFuzzerBase {
    @Override
    protected EmbeddedChannel setUp() {
        HttpClientCodec clientCodec = new HttpClientCodec();
        return new EmbeddedChannel(
            clientCodec,
            new HttpObjectAggregator(65536),
            new WebSocketClientProtocolHandler(WebSocketClientProtocolConfig.newBuilder().build()),
            new ChannelInboundHandlerAdapter() {
                @Override
                public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                    if (isExpected(cause)) {
                        ctx.close();
                        return;
                    }
                    super.exceptionCaught(ctx, cause);
                }
            }
        );
    }

    @Override
    protected void onException(Exception e) {
        if (isExpected(e)) {
            return;
        }
        super.onException(e);
    }

    private static boolean isExpected(Throwable cause) {
        return cause instanceof WebSocketHandshakeException
            || cause instanceof CorruptedWebSocketFrameException
            || cause instanceof TooLongFrameException
            || cause instanceof PrematureChannelClosureException
            || cause instanceof ClosedChannelException
            || (cause instanceof DecoderException && cause.getCause() instanceof NumberFormatException);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws Exception {
        new WebSocketClientProtocolHandlerFuzzer().test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(WebSocketClientProtocolHandlerFuzzer.class).fuzz();
    }
}

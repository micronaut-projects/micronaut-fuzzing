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
package io.netty.handler.codec.http;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.http2.Http2ClientUpgradeCodec;
import io.netty.handler.codec.http2.Http2Exception;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;

import javax.net.ssl.SSLException;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
public class HttpClientUpgradeHandlerFuzzer extends HandlerFuzzerBase {
    public HttpClientUpgradeHandlerFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        HttpClientCodec clientCodec = new HttpClientCodec();
        channel.pipeline()
            .addLast(clientCodec)
            .addLast(new HttpClientUpgradeHandler(clientCodec, new Http2ClientUpgradeCodec(Http2FrameCodecBuilder.forClient().build()), 1024))
            .addLast(new ChannelInboundHandlerAdapter() {
                @Override
                public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                    if (cause instanceof Http2Exception || cause instanceof IllegalStateException) {
                        return;
                    }
                    super.exceptionCaught(ctx, cause);
                }
            });

        channel.writeOutbound(new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/", channel.alloc().buffer()));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new HttpClientUpgradeHandlerFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HttpClientUpgradeHandlerFuzzer.class).fuzz();
    }
}

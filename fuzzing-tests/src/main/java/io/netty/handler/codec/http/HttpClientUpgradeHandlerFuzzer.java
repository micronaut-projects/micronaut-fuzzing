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
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.http2.Http2ClientUpgradeCodec;
import io.netty.handler.codec.http2.Http2Exception;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;
import io.netty.handler.codec.http2.Http2FrameStreamException;


/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
public class HttpClientUpgradeHandlerFuzzer extends HandlerFuzzerBase {
    @Override
    protected EmbeddedChannel setUp() {
        EmbeddedChannel channel = new EmbeddedChannel();
        HttpClientCodec clientCodec = new HttpClientCodec();
        channel.pipeline()
            .addLast(clientCodec)
            .addLast(new HttpClientUpgradeHandler(clientCodec, new Http2ClientUpgradeCodec(Http2FrameCodecBuilder.forClient().build()), 1024))
            .addLast(new ChannelInboundHandlerAdapter() {
                @Override
                public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                    if (isExpected(cause)) {
                        return;
                    }
                    super.exceptionCaught(ctx, cause);
                }
            });

        channel.writeOutbound(new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/", channel.alloc().buffer()));
        return channel;
    }

    @Override
    protected void onException(Exception e) {
        if (isExpected(e)) {
            return;
        }
        super.onException(e);
    }

    private static boolean isExpected(Throwable cause) {
        if (cause instanceof Http2Exception) {
            // HTTP/2 protocol errors after the upgrade. An Http2Exception that wraps another
            // exception may hide a bug, so only accept those whose causes are all Http2Exceptions.
            return isHttp2ProtocolError(cause);
        }
        if (cause instanceof Http2FrameStreamException) {
            return isHttp2ProtocolError(cause.getCause());
        }
        if (cause instanceof TooLongHttpContentException) {
            // The 101 response is aggregated with the configured maxContentLength.
            return isThrownBy(cause, HttpObjectAggregator.class, "handleOversizedMessage");
        }
        if (cause.getClass() == IllegalStateException.class) {
            // "Read HTTP response without requesting protocol switch" and
            // "Switching Protocols response with unexpected UPGRADE protocol"
            return isThrownBy(cause, HttpClientUpgradeHandler.class, "decode");
        }
        return false;
    }

    private static boolean isHttp2ProtocolError(Throwable cause) {
        for (Throwable t = cause; t != null; t = t.getCause()) {
            if (!(t instanceof Http2Exception)) {
                return false;
            }
        }
        return cause != null;
    }

    private static boolean isThrownBy(Throwable cause, Class<?> type, String method) {
        StackTraceElement[] trace = cause.getStackTrace();
        return trace.length > 0
            && trace[0].getClassName().equals(type.getName())
            && trace[0].getMethodName().equals(method);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        new HttpClientUpgradeHandlerFuzzer().test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HttpClientUpgradeHandlerFuzzer.class).fuzz();
    }
}

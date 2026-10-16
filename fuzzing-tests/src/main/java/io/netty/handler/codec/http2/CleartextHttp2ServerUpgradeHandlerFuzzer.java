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
package io.netty.handler.codec.http2;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.PrematureChannelClosureException;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpServerUpgradeHandler;
import io.netty.util.AsciiString;

import java.nio.channels.ClosedChannelException;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
@Dict({
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    "Upgrade: h2c\r\n",
    "HTTP2-Settings",
    "Connection: Upgrade, HTTP2-Settings\r\n",
    "h2c"
})
public class CleartextHttp2ServerUpgradeHandlerFuzzer extends HandlerFuzzerBase {
    @Override
    protected EmbeddedChannel setUp() {
        EmbeddedChannel channel = new EmbeddedChannel();
        HttpServerCodec serverCodec = new HttpServerCodec();
        HttpServerUpgradeHandler upgradeHandler = new HttpServerUpgradeHandler(serverCodec, protocol -> {
            if (AsciiString.contentEquals(Http2CodecUtil.HTTP_UPGRADE_PROTOCOL_NAME, protocol)) {
                return new Http2ServerUpgradeCodec(Http2FrameCodecBuilder.forServer().build());
            }
            return null;
        }, 1024);

        channel.pipeline()
            .addLast(new CleartextHttp2ServerUpgradeHandler(
                serverCodec,
                upgradeHandler,
                Http2FrameCodecBuilder.forServer().build()
            ));
        return channel;
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof Http2Exception
            || e instanceof Http2FrameStreamException
            || e instanceof PrematureChannelClosureException
            || e instanceof ClosedChannelException
            || (e instanceof DecoderException && e.getCause() instanceof Http2Exception)
            || isUpgradeAfterCloseNpe(e)
            || isInvalidUpgradeRequestTarget(e)) {
            return;
        }
        super.onException(e);
    }

    /**
     * Http2FrameCodec does not find the upgrade stream when the upgrade happens after the channel was
     * closed, e.g. for a pipelined upgrade request after a request with {@code Connection: close}.
     * Fixed by <a href="https://github.com/netty/netty/pull/17871">netty#17871</a>.
     */
    private static boolean isUpgradeAfterCloseNpe(Exception e) {
        if (!(e instanceof NullPointerException)) {
            return false;
        }
        StackTraceElement[] trace = e.getStackTrace();
        return trace.length > 0
            && trace[0].getClassName().equals(Http2FrameCodec.class.getName())
            && trace[0].getMethodName().equals("userEventTriggered");
    }

    /**
     * The request target of the upgrade request can not always be converted to HTTP/2 headers (invalid
     * {@code :path} characters, or an absolute URI that {@link java.net.URI} rejects).
     * Fixed by <a href="https://github.com/netty/netty/pull/17869">netty#17869</a>.
     */
    private static boolean isInvalidUpgradeRequestTarget(Exception e) {
        if (!(e instanceof IllegalArgumentException)) {
            return false;
        }
        StackTraceElement[] trace = e.getStackTrace();
        for (int i = 0; i < trace.length - 1; i++) {
            if (trace[i].getClassName().equals(HttpConversionUtil.class.getName())
                && trace[i].getMethodName().equals("toHttp2Headers")) {
                return trace[i + 1].getClassName().equals(InboundHttpToHttp2Adapter.class.getName())
                    && trace[i + 1].getMethodName().equals("handle");
            }
        }
        return false;
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws Exception {
        new CleartextHttp2ServerUpgradeHandlerFuzzer().test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(CleartextHttp2ServerUpgradeHandlerFuzzer.class).fuzz();
    }
}

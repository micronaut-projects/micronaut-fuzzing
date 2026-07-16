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
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.PrematureChannelClosureException;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpServerUpgradeHandler;
import io.netty.util.AsciiString;

import javax.net.ssl.SSLException;
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
    public CleartextHttp2ServerUpgradeHandlerFuzzer(FuzzedDataProvider fuzzedDataProvider) {
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
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof Http2Exception
            || e instanceof Http2FrameStreamException
            || e instanceof PrematureChannelClosureException
            || e instanceof ClosedChannelException
            || e instanceof DecoderException && e.getCause() instanceof Http2Exception) {
            return;
        }
        super.onException(e);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new CleartextHttp2ServerUpgradeHandlerFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(CleartextHttp2ServerUpgradeHandlerFuzzer.class).fuzz();
    }
}

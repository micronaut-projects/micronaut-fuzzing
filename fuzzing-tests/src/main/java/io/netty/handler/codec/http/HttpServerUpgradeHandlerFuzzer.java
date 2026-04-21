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
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.PrematureChannelClosureException;
import io.netty.handler.codec.http2.Http2CodecUtil;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;
import io.netty.handler.codec.http2.Http2ServerUpgradeCodec;
import io.netty.util.AsciiString;

import javax.net.ssl.SSLException;
import java.nio.channels.ClosedChannelException;

@FuzzTarget
@HttpDict
public class HttpServerUpgradeHandlerFuzzer extends HandlerFuzzerBase {
    public HttpServerUpgradeHandlerFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        HttpServerCodec serverCodec = new HttpServerCodec();
        channel.pipeline()
            .addLast(serverCodec)
            .addLast(new HttpServerUpgradeHandler(serverCodec, protocol -> {
                if (AsciiString.contentEquals(Http2CodecUtil.HTTP_UPGRADE_PROTOCOL_NAME, protocol)) {
                    return new Http2ServerUpgradeCodec(Http2FrameCodecBuilder.forServer().build());
                } else {
                    return null;
                }
            }, 1024));
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof PrematureChannelClosureException || e instanceof ClosedChannelException) {
            return;
        }
        super.onException(e);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new HttpServerUpgradeHandlerFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HttpServerUpgradeHandlerFuzzer.class).fuzz();
    }
}

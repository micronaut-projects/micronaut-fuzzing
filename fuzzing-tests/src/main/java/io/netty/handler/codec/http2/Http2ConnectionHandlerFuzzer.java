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

import javax.net.ssl.SSLException;
import java.nio.channels.ClosedChannelException;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
@Dict({
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    "\u0000\u0000\u0000\u0004\u0000\u0000\u0000\u0000\u0000",
    "\u0000\u0000\b\u0006\u0000\u0000\u0000\u0000\u0000",
    "\u0000\u0000\u0000\u0004\u0001\u0000\u0000\u0000\u0000"
})
public class Http2ConnectionHandlerFuzzer extends HandlerFuzzerBase {
    public Http2ConnectionHandlerFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(new Http2ConnectionHandlerBuilder()
                .server(true)
                .frameListener(new Http2FrameAdapter())
                .build());
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
        var fuzzer = new Http2ConnectionHandlerFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(Http2ConnectionHandlerFuzzer.class).fuzz();
    }
}

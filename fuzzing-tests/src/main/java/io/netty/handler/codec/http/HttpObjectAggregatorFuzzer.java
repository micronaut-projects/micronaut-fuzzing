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
import io.netty.handler.codec.PrematureChannelClosureException;

import javax.net.ssl.SSLException;
import java.nio.channels.ClosedChannelException;

@FuzzTarget
@HttpDict
public class HttpObjectAggregatorFuzzer extends HandlerFuzzerBase {
    public HttpObjectAggregatorFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(fuzzedDataProvider.consumeBoolean() ? new HttpClientCodec() : new HttpServerCodec())
            .addLast(new HttpObjectAggregator(1024))
            .addLast(new ChannelInboundHandlerAdapter() {
                @Override
                public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                    if (cause instanceof TooLongHttpContentException || cause instanceof PrematureChannelClosureException || cause instanceof ClosedChannelException) {
                        ctx.close();
                        return;
                    }
                    super.exceptionCaught(ctx, cause);
                }
            });
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new HttpObjectAggregatorFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HttpObjectAggregatorFuzzer.class).fuzz();
    }
}

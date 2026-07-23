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
package io.netty.handler.codec.base64;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.EmbeddedChannelFuzzerBase;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@Dict({
    "base64", "hello", "foobar", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
})
public class Base64EncoderFuzzer extends EmbeddedChannelFuzzerBase {
    private static final Base64Dialect[] DIALECTS = Base64Dialect.values();
    private final boolean breakLines;
    private final Base64Dialect dialect;

    public Base64EncoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        breakLines = fuzzedDataProvider.consumeBoolean();
        dialect = DIALECTS[fuzzedDataProvider.consumeInt(0, DIALECTS.length - 1)];
    }

    @Override
    protected EmbeddedChannel setUp() {
        return new EmbeddedChannel(
            new Base64Encoder(breakLines, dialect),
            new InboundToOutboundHandler()
        );
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        var fuzzer = new Base64EncoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(Base64EncoderFuzzer.class).fuzz();
    }

    private static final class InboundToOutboundHandler extends ChannelInboundHandlerAdapter {
        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            ctx.writeAndFlush(msg);
        }
    }
}

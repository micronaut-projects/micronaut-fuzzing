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
package io.netty.handler.codec.haproxy;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.TooLongFrameException;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
@Dict({"PROXY ", " TCP4 ", " TCP6 ", " UNKNOWN", "\r\n", "\r\n\r\n\0\r\nQUIT\n"})
public class HAProxyMessageDecoderFuzzer extends HandlerFuzzerBase {
    private final int maxTlvSize;
    private final boolean failFast;

    public HAProxyMessageDecoderFuzzer(int maxTlvSize, boolean failFast) {
        this.maxTlvSize = maxTlvSize;
        this.failFast = failFast;
    }

    @Override
    protected EmbeddedChannel setUp() {
        EmbeddedChannel channel = new EmbeddedChannel();
        channel.pipeline()
            .addLast(new HAProxyMessageDecoder(maxTlvSize, failFast))
            .addLast(new ChannelInboundHandlerAdapter() {
                @Override
                public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                    if (isExpected(cause)) {
                        return;
                    }
                    super.exceptionCaught(ctx, cause);
                }
            });
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
        return cause instanceof HAProxyProtocolException
            || cause instanceof TooLongFrameException
            || cause instanceof IllegalArgumentException
            || cause instanceof IndexOutOfBoundsException
            || cause instanceof DecoderException && cause.getCause() != null && isExpected(cause.getCause());
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        int maxTlvSize = fuzzedDataProvider.consumeInt(0, 1024);
        boolean failFast = fuzzedDataProvider.consumeBoolean();
        new HAProxyMessageDecoderFuzzer(maxTlvSize, failFast).test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HAProxyMessageDecoderFuzzer.class).fuzz();
    }
}

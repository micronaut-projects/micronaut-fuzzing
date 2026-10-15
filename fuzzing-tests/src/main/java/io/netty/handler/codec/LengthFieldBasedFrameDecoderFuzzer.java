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
package io.netty.handler.codec;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.HandlerFuzzerBase;


/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
public class LengthFieldBasedFrameDecoderFuzzer extends HandlerFuzzerBase {
    private final int maxFrameLength;
    private final int lengthFieldOffset;
    private final int lengthFieldLength;

    public LengthFieldBasedFrameDecoderFuzzer(int maxFrameLength, int lengthFieldOffset, int lengthFieldLength) {
        this.maxFrameLength = maxFrameLength;
        this.lengthFieldOffset = lengthFieldOffset;
        this.lengthFieldLength = lengthFieldLength;
    }

    @Override
    protected EmbeddedChannel setUp() {
        EmbeddedChannel channel = new EmbeddedChannel();
        channel.pipeline()
            .addLast(new LengthFieldBasedFrameDecoder(maxFrameLength, lengthFieldOffset, lengthFieldLength))
            .addLast(new ChannelInboundHandlerAdapter() {
                @Override
                public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                    if (cause instanceof TooLongFrameException || cause instanceof CorruptedFrameException) {
                        return;
                    }
                    super.exceptionCaught(ctx, cause);
                }
            });
        return channel;
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        int maxFrameLength = fuzzedDataProvider.consumeInt(16, 1024);
        int lengthFieldOffset = fuzzedDataProvider.consumeInt(0, 5);
        int lengthFieldLength = fuzzedDataProvider.pickValue(new int[] { 1, 2, 4, 8 });
        new LengthFieldBasedFrameDecoderFuzzer(maxFrameLength, lengthFieldOffset, lengthFieldLength).test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(LengthFieldBasedFrameDecoderFuzzer.class).fuzz();
    }
}

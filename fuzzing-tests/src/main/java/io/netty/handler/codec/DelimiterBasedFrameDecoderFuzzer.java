package io.netty.handler.codec;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.util.CharsetUtil;

import javax.net.ssl.SSLException;

@FuzzTarget
@HttpDict
public class DelimiterBasedFrameDecoderFuzzer extends HandlerFuzzerBase {
    public DelimiterBasedFrameDecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(new DelimiterBasedFrameDecoder(128, Unpooled.copiedBuffer("ABC", CharsetUtil.UTF_8)))
            .addLast(new ChannelInboundHandlerAdapter() {
                @Override
                public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                    if (cause instanceof TooLongFrameException) {
                        return;
                    }
                    super.exceptionCaught(ctx, cause);
                }
            });
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new DelimiterBasedFrameDecoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(DelimiterBasedFrameDecoderFuzzer.class).fuzz();
    }
}

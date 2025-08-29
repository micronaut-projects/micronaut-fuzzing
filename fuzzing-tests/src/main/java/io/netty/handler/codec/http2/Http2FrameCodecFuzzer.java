package io.netty.handler.codec.http2;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.HandlerFuzzerBase;

import javax.net.ssl.SSLException;

@FuzzTarget
@HttpDict
public class Http2FrameCodecFuzzer extends HandlerFuzzerBase {
    public Http2FrameCodecFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(Http2FrameCodecBuilder.forClient().build())
            .addLast(new ChannelInboundHandlerAdapter() {
                @Override
                public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                    if (cause instanceof Http2Exception) {
                        return;
                    }
                    super.exceptionCaught(ctx, cause);
                }
            });
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new Http2FrameCodecFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(Http2FrameCodecFuzzer.class).fuzz();
    }
}

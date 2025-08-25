package io.netty.handler.codec.compression;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.DecoderException;

import javax.net.ssl.SSLException;

@FuzzTarget
@HttpDict
public class FastLzFrameDecoderFuzzer extends DecompressorFuzzerBase {
    public FastLzFrameDecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(new FastLzFrameDecoder(fuzzedDataProvider.consumeBoolean()))
            .addLast(new ChannelInboundHandlerAdapter() {
                @Override
                public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                    if (cause instanceof DecoderException) {
                        return;
                    }
                    super.exceptionCaught(ctx, cause);
                }
            });
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new FastLzFrameDecoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(FastLzFrameDecoderFuzzer.class).fuzz();
    }
}

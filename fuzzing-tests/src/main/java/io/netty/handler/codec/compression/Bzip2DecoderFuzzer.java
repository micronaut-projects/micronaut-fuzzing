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
public class Bzip2DecoderFuzzer extends DecompressorFuzzerBase {
    public Bzip2DecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(new Bzip2Decoder())
            .addLast(new ChannelInboundHandlerAdapter() {
                @Override
                public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                    if (cause instanceof DecoderException && cause.getCause() instanceof ArrayIndexOutOfBoundsException) {
                        return;
                    }
                    super.exceptionCaught(ctx, cause);
                }
            });
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new Bzip2DecoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(Bzip2DecoderFuzzer.class).fuzz();
    }
}

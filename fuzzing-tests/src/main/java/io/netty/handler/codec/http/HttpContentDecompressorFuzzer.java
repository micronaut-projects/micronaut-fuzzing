package io.netty.handler.codec.http;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.compression.DecompressionException;

import javax.net.ssl.SSLException;

@FuzzTarget
@HttpDict
public class HttpContentDecompressorFuzzer extends HandlerFuzzerBase {
    public HttpContentDecompressorFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        HttpClientCodec clientCodec = new HttpClientCodec();
        channel.pipeline()
            .addLast(clientCodec)
            .addLast(new HttpContentDecompressor())
            .addLast(new ChannelInboundHandlerAdapter() {
                @Override
                public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                    if (cause instanceof DecompressionException) {
                        ctx.close();
                        return;
                    }
                    super.exceptionCaught(ctx, cause);
                }
            });
        outputCpuTime = inputCpuTime;
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new HttpContentDecompressorFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HttpContentDecompressorFuzzer.class).fuzz();
    }
}

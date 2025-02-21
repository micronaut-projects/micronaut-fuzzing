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
                    if (cause instanceof TooLongHttpContentException || cause instanceof PrematureChannelClosureException) {
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

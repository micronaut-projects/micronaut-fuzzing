package io.netty.handler.codec.http;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.http2.Http2ClientUpgradeCodec;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;

import javax.net.ssl.SSLException;

@FuzzTarget
@HttpDict
public class HttpClientUpgradeHandlerFuzzer extends HandlerFuzzerBase {
    public HttpClientUpgradeHandlerFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        HttpClientCodec clientCodec = new HttpClientCodec();
        channel.pipeline()
            .addLast(clientCodec)
            .addLast(new HttpClientUpgradeHandler(clientCodec, new Http2ClientUpgradeCodec(Http2FrameCodecBuilder.forClient().build()), 1024));

        channel.writeOutbound(new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/", channel.alloc().buffer()));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new HttpClientUpgradeHandlerFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HttpClientUpgradeHandlerFuzzer.class).fuzz();
    }
}

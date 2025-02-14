package io.netty.handler.codec.http;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.http2.Http2CodecUtil;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;
import io.netty.handler.codec.http2.Http2ServerUpgradeCodec;
import io.netty.util.AsciiString;

import javax.net.ssl.SSLException;

@FuzzTarget
@HttpDict
public class HttpServerUpgradeHandlerFuzzer extends HandlerFuzzerBase {
    public HttpServerUpgradeHandlerFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        HttpServerCodec serverCodec = new HttpServerCodec();
        channel.pipeline()
            .addLast(serverCodec)
            .addLast(new HttpServerUpgradeHandler(serverCodec, protocol -> {
                if (AsciiString.contentEquals(Http2CodecUtil.HTTP_UPGRADE_PROTOCOL_NAME, protocol)) {
                    return new Http2ServerUpgradeCodec(Http2FrameCodecBuilder.forServer().build());
                } else {
                    return null;
                }
            }, 1024));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new HttpServerUpgradeHandlerFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HttpServerUpgradeHandlerFuzzer.class).fuzz();
    }
}

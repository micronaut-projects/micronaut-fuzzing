package io.netty.handler.codec.http2;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.handler.HandlerFuzzerBase;

import javax.net.ssl.SSLException;

@FuzzTarget
@HttpDict
public class Http2FrameCodecFuzzer extends HandlerFuzzerBase {
    public Http2FrameCodecFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(Http2FrameCodecBuilder.forClient().build());
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof Http2Exception || e instanceof Http2FrameStreamException) {
            return;
        }
        super.onException(e);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new Http2FrameCodecFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(Http2FrameCodecFuzzer.class).fuzz();
    }
}

package io.netty.handler.codec;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.handler.HandlerFuzzerBase;

import javax.net.ssl.SSLException;

@FuzzTarget
@HttpDict
public class LineBasedFrameDecoderFuzzer extends HandlerFuzzerBase {
    public LineBasedFrameDecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(new LineBasedFrameDecoder(128));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new LineBasedFrameDecoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof TooLongFrameException) {
            return;
        }
        super.onException(e);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(LineBasedFrameDecoderFuzzer.class).fuzz();
    }
}

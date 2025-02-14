package io.netty.handler.codec.string;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.handler.codec.TooLongFrameException;

import javax.net.ssl.SSLException;
import java.nio.charset.StandardCharsets;

@FuzzTarget
@HttpDict
public class StringDecoderFuzzer extends HandlerFuzzerBase {
    public StringDecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(new LineBasedFrameDecoder(80))
            .addLast(new StringDecoder(fuzzedDataProvider.consumeBoolean() ? StandardCharsets.UTF_8 : StandardCharsets.US_ASCII));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new StringDecoderFuzzer(fuzzedDataProvider);
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
        LocalJazzerRunner.create(StringDecoderFuzzer.class).fuzz();
    }
}

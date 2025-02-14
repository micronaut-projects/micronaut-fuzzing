package io.netty.handler.codec;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.handler.HandlerFuzzerBase;

import javax.net.ssl.SSLException;

@FuzzTarget
@HttpDict
public class LengthFieldBasedFrameDecoderFuzzer extends HandlerFuzzerBase {
    public LengthFieldBasedFrameDecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(new LengthFieldBasedFrameDecoder(fuzzedDataProvider.consumeInt(16, 1024), fuzzedDataProvider.consumeInt(0, 5), fuzzedDataProvider.pickValue(new int[] { 1, 2, 4, 8 })));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new LengthFieldBasedFrameDecoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof TooLongFrameException || e instanceof CorruptedFrameException) {
            return;
        }
        super.onException(e);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(LengthFieldBasedFrameDecoderFuzzer.class).fuzz();
    }
}

package io.netty.handler.codec.json;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.TooLongFrameException;

import javax.net.ssl.SSLException;

@FuzzTarget
@HttpDict
public class JsonObjectDecoderFuzzer extends HandlerFuzzerBase {
    public JsonObjectDecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(new JsonObjectDecoder(fuzzedDataProvider.consumeInt(10, 1024), fuzzedDataProvider.consumeBoolean()));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new JsonObjectDecoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof CorruptedFrameException || e instanceof TooLongFrameException) {
            return;
        }
        super.onException(e);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(JsonObjectDecoderFuzzer.class).fuzz();
    }
}

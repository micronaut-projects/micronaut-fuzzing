package io.netty.handler.codec.base64;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.DecoderException;

import javax.net.ssl.SSLException;

@FuzzTarget
@HttpDict
public class Base64DecoderFuzzer extends HandlerFuzzerBase {
    public Base64DecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(new Base64Decoder());
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new Base64DecoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof DecoderException && e.getCause() instanceof IllegalArgumentException) {
            return;
        }
        super.onException(e);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(Base64DecoderFuzzer.class).fuzz();
    }
}

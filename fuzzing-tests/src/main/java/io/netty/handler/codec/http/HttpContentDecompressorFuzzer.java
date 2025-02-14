package io.netty.handler.codec.http;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.handler.HandlerFuzzerBase;

import javax.net.ssl.SSLException;

@FuzzTarget
@HttpDict
public class HttpContentDecompressorFuzzer extends HandlerFuzzerBase {
    public HttpContentDecompressorFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        HttpClientCodec clientCodec = new HttpClientCodec();
        channel.pipeline()
            .addLast(clientCodec)
            .addLast(new HttpContentDecompressor());
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new HttpContentDecompressorFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HttpContentDecompressorFuzzer.class).fuzz();
    }
}

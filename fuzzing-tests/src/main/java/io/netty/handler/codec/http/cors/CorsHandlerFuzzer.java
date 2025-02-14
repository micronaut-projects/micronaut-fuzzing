package io.netty.handler.codec.http.cors;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.http.HttpServerCodec;

import javax.net.ssl.SSLException;

@FuzzTarget
@HttpDict
public class CorsHandlerFuzzer extends HandlerFuzzerBase {
    public CorsHandlerFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        HttpServerCodec serverCodec = new HttpServerCodec();
        channel.pipeline()
            .addLast(serverCodec)
            .addLast(new CorsHandler(CorsConfigBuilder.forAnyOrigin().build()));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new CorsHandlerFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(CorsHandlerFuzzer.class).fuzz();
    }
}

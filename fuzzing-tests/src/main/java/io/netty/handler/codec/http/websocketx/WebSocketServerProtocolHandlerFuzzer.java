package io.netty.handler.codec.http.websocketx;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.http.HttpServerCodec;

import javax.net.ssl.SSLException;

@FuzzTarget
@HttpDict
public class WebSocketServerProtocolHandlerFuzzer extends HandlerFuzzerBase {
    public WebSocketServerProtocolHandlerFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        HttpServerCodec serverCodec = new HttpServerCodec();
        channel.pipeline()
            .addLast(serverCodec)
            .addLast(new WebSocketServerProtocolHandler(WebSocketServerProtocolConfig.newBuilder().build()));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new WebSocketServerProtocolHandlerFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(WebSocketServerProtocolHandlerFuzzer.class).fuzz();
    }
}

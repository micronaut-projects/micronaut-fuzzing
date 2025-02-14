package io.netty.handler.codec.compression;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;

import javax.net.ssl.SSLException;

@FuzzTarget
@HttpDict
public class JZlibDecoderFuzzer extends DecompressorFuzzerBase {
    public JZlibDecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(new JZlibDecoder(fuzzedDataProvider.consumeInt(0, 1024)));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new JZlibDecoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(JZlibDecoderFuzzer.class).fuzz();
    }
}

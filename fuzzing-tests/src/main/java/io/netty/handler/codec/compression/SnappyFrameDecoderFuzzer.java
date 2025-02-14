package io.netty.handler.codec.compression;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;

import javax.net.ssl.SSLException;

@FuzzTarget
@HttpDict
public class SnappyFrameDecoderFuzzer extends DecompressorFuzzerBase {
    public SnappyFrameDecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(new SnappyFrameDecoder(fuzzedDataProvider.consumeBoolean()));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new SnappyFrameDecoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(SnappyFrameDecoderFuzzer.class).fuzz();
    }
}

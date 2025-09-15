package io.netty.handler.codec.compression;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.handler.codec.DecoderException;

import javax.net.ssl.SSLException;

@FuzzTarget
@HttpDict
public class Bzip2DecoderFuzzer extends DecompressorFuzzerBase {
    public Bzip2DecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline().addLast(new Bzip2Decoder());
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof DecoderException && (e.getCause() instanceof ArrayIndexOutOfBoundsException || e.getCause() instanceof IndexOutOfBoundsException)) {
            return;
        }
        super.onException(e);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new Bzip2DecoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(Bzip2DecoderFuzzer.class).fuzz();
    }
}

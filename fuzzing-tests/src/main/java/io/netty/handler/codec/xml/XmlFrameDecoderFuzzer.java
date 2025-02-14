package io.netty.handler.codec.xml;

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
public class XmlFrameDecoderFuzzer extends HandlerFuzzerBase {
    public XmlFrameDecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(new XmlFrameDecoder(fuzzedDataProvider.consumeInt(10, 1024)));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new XmlFrameDecoderFuzzer(fuzzedDataProvider);
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
        LocalJazzerRunner.create(XmlFrameDecoderFuzzer.class).fuzz();
    }
}

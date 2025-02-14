package io.netty.handler.codec;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.buffer.Unpooled;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.util.CharsetUtil;

import javax.net.ssl.SSLException;

@FuzzTarget
@HttpDict
public class DelimiterBasedFrameDecoderFuzzer extends HandlerFuzzerBase {
    public DelimiterBasedFrameDecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(new DelimiterBasedFrameDecoder(128, Unpooled.copiedBuffer("ABC", CharsetUtil.UTF_8)));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new DelimiterBasedFrameDecoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof TooLongFrameException) {
            return;
        }
        super.onException(e);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(DelimiterBasedFrameDecoderFuzzer.class).fuzz();
    }
}

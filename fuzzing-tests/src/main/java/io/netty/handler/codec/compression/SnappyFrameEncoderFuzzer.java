/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.netty.handler.codec.compression;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.EmbeddedChannelFuzzerBase;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.EncoderException;
import io.netty.handler.codec.PrematureChannelClosureException;

import javax.net.ssl.SSLException;
import java.nio.channels.ClosedChannelException;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
@Dict({
    "snappy", "content-encoding: snappy\r\n", "hello", "foobar"
})
public class SnappyFrameEncoderFuzzer extends EmbeddedChannelFuzzerBase {
    public SnappyFrameEncoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        super(new EmbeddedChannel(nextEncoder(fuzzedDataProvider)));
        inputCpuTime = 200;
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof CompressionException
            || e instanceof PrematureChannelClosureException
            || e instanceof ClosedChannelException
            || e instanceof EncoderException && e.getCause() instanceof CompressionException) {
            return;
        }
        super.onException(e);
    }

    private static SnappyFrameEncoder nextEncoder(FuzzedDataProvider fuzzedDataProvider) {
        if (fuzzedDataProvider.consumeBoolean()) {
            return SnappyFrameEncoder.snappyEncoderWithJumboFrames();
        }
        return new SnappyFrameEncoder();
    }

    @Override
    protected boolean isOutbound() {
        return true;
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new SnappyFrameEncoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(SnappyFrameEncoderFuzzer.class).fuzz();
    }
}

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
package io.netty.handler.codec.redis;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.PrematureChannelClosureException;

import javax.net.ssl.SSLException;
import java.nio.channels.ClosedChannelException;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@Dict({
    "SEP", "+OK\r\n", "-ERR error\r\n", ":1\r\n", "$5\r\nhello\r\n", "$-1\r\n",
    "*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n", "PING\r\n", "SET key value\r\n"
})
public class RedisDecoderFuzzer extends HandlerFuzzerBase {
    private static final int MAX_INLINE_MESSAGE_LENGTH = 65536;

    public RedisDecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(new RedisDecoder(
                fuzzedDataProvider.consumeInt(1, MAX_INLINE_MESSAGE_LENGTH),
                FixedRedisMessagePool.INSTANCE,
                fuzzedDataProvider.consumeBoolean()
            ));
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof RedisCodecException
            || e instanceof PrematureChannelClosureException
            || e instanceof ClosedChannelException
            || e instanceof DecoderException && e.getCause() instanceof RedisCodecException) {
            return;
        }
        super.onException(e);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new RedisDecoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(RedisDecoderFuzzer.class).fuzz();
    }
}

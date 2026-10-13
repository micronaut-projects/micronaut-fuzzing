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
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.DecoderException;

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
    private final int maxInlineMessageLength;
    private final boolean decodeInlineCommands;

    public RedisDecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        maxInlineMessageLength = fuzzedDataProvider.consumeInt(1, MAX_INLINE_MESSAGE_LENGTH);
        decodeInlineCommands = fuzzedDataProvider.consumeBoolean();
    }

    @Override
    protected EmbeddedChannel setUp() {
        return new EmbeddedChannel(new RedisDecoder(
            maxInlineMessageLength,
            FixedRedisMessagePool.INSTANCE,
            decodeInlineCommands
        ));
    }

    @Override
    protected void onException(Exception e) {
        // RedisCodecException is not a DecoderException, so ByteToMessageDecoder wraps it in one. RedisDecoder
        // also wraps any unexpected exception (NPE, IOOBE, ...) in a RedisCodecException with that cause, so
        // only ignore the validation failures it throws itself, which never have a cause.
        Throwable t = e instanceof DecoderException && e.getCause() instanceof RedisCodecException ? e.getCause() : e;
        if (t instanceof RedisCodecException && (t.getCause() == null || isKnownLineFeedBug(t.getCause()))) {
            return;
        }
        super.onException(e);
    }

    /**
     * RedisDecoder.readLine throws an IllegalArgumentException for a line that starts with LF, because it computes a
     * negative length for the content before the CR. Remove once https://github.com/netty/netty/pull/17793 is released.
     */
    private static boolean isKnownLineFeedBug(Throwable cause) {
        if (!(cause instanceof IllegalArgumentException)) {
            return false;
        }
        for (StackTraceElement element : cause.getStackTrace()) {
            if (element.getClassName().equals(RedisDecoder.class.getName())) {
                return element.getMethodName().equals("readLine");
            }
        }
        return false;
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        var fuzzer = new RedisDecoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(RedisDecoderFuzzer.class).fuzz();
    }
}

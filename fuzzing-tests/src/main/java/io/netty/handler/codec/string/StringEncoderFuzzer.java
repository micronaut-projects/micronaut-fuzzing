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
package io.netty.handler.codec.string;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.EncoderException;
import io.netty.util.LeakPresenceDetector;
import io.netty.util.concurrent.FastThreadLocalThread;

import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.IllegalCharsetNameException;
import java.nio.charset.UnsupportedCharsetException;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@Dict({
    "UTF-8", "US-ASCII", "ISO-8859-1", "UTF-16", "UTF-16BE", "UTF-16LE",
    "hello", "foobar", "charset", "line\r\nbreak"
})
public class StringEncoderFuzzer {
    private static final int MAX_CHARSET_NAME_CHARS = 64;
    private static final int MAX_INPUT_CHARS = 4096;

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        FastThreadLocalThread.runWithFastThreadLocal(() -> test0(fuzzedDataProvider));
    }

    private static void test0(FuzzedDataProvider fuzzedDataProvider) {
        Charset charset = nextCharset(fuzzedDataProvider);
        if (charset == null) {
            return;
        }
        CharSequence input = nextCharSequence(fuzzedDataProvider);
        EmbeddedChannel channel = new EmbeddedChannel(new StringEncoder(charset));
        try {
            channel.writeOutbound(input);
        } catch (EncoderException e) {
            if (input.length() != 0 || !"StringEncoder must produce at least one message.".equals(e.getMessage())) {
                throw e;
            }
        } finally {
            channel.finishAndReleaseAll();
        }
        LeakPresenceDetector.check();
    }

    private static Charset nextCharset(FuzzedDataProvider fuzzedDataProvider) {
        String charsetName = fuzzedDataProvider.consumeString(MAX_CHARSET_NAME_CHARS);
        try {
            return Charset.forName(charsetName);
        } catch (IllegalCharsetNameException | UnsupportedCharsetException e) {
            return null;
        }
    }

    private static CharSequence nextCharSequence(FuzzedDataProvider fuzzedDataProvider) {
        String value = fuzzedDataProvider.consumeString(MAX_INPUT_CHARS);
        return switch (fuzzedDataProvider.consumeInt(0, 2)) {
            case 0 -> value;
            case 1 -> new StringBuilder(value);
            case 2 -> CharBuffer.wrap(value);
            default -> throw new IllegalStateException("Unexpected CharSequence type");
        };
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(StringEncoderFuzzer.class).fuzz();
    }
}

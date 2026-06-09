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
package io.micronaut.fuzzing.http;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.handler.codec.http.cookie.Cookie;
import io.netty.handler.codec.http.cookie.DefaultCookie;
import io.netty.handler.codec.http.cookie.ServerCookieDecoder;
import io.netty.handler.codec.http.cookie.ServerCookieEncoder;

import java.util.Collection;

@FuzzTarget
@Dict({
    "session=abc123",
    "theme=dark",
    "id=42",

    "session=abc123; theme=dark",
    "a=1; b=2; c=3",

    "name=value; Path=/; HttpOnly",
    "name=value; Secure; SameSite=Strict",
    "name=value; Domain=example.com; Max-Age=3600",
    "name=value; Expires=Thu, 01 Jan 2099 00:00:00 GMT",

    "=",
    "a=",
    "=b",
    ";",
    ";;",
    "name=v1; name=v2",
    "\"quoted\"=value",
    "name=\"quoted value\"",

    "name=\t",
    " name=value",
    "name =value",
    "name= value",
})
public class CookieParsingTarget {

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        int scenario = data.consumeInt(0, 3);
        switch (scenario) {
            case 0 -> decodeStrict(data);
            case 1 -> decodeLax(data);
            case 2 -> encodeDecodeRoundTrip(data);
        }
    }

    private static void decodeStrict(FuzzedDataProvider data) {
        String header = data.consumeRemainingAsString();
        try {
            Collection<Cookie> cookies = ServerCookieDecoder.STRICT.decode(header);
            for (Cookie c : cookies) {
                c.name();
                c.value();
            }
        } catch (IllegalArgumentException ignored) {
        }
    }

    private static void decodeLax(FuzzedDataProvider data) {
        String header = data.consumeRemainingAsString();
        try {
            Collection<Cookie> cookies = ServerCookieDecoder.LAX.decode(header);
            for (Cookie c : cookies) {
                c.name();
                c.value();
            }
        } catch (IllegalArgumentException ignored) {
        }
    }

    private static void encodeDecodeRoundTrip(FuzzedDataProvider data) {
        String name = data.consumeString(32);
        String value = data.consumeString(64);
        String encoded;
        try {
            DefaultCookie cookie = new DefaultCookie(name, value);
            encoded = ServerCookieEncoder.STRICT.encode(cookie);
        } catch (IllegalArgumentException ignored) {
            return;
        }
        ServerCookieDecoder.STRICT.decode(encoded);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(CookieParsingTarget.class).fuzz();
    }
}

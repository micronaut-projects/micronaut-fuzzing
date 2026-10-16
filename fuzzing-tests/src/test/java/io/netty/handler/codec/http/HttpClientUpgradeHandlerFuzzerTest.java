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
package io.netty.handler.codec.http;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

class HttpClientUpgradeHandlerFuzzerTest {
    @Test
    void successfulUpgrade() {
        run("HTTP/1.1 101 Switching Protocols\r\n"
            + "Connection: Upgrade\r\n"
            + "Upgrade: h2c\r\n"
            + "\r\n"
            + "SEP"
            // empty SETTINGS frame
            + "\0\0\0\4\0\0\0\0\0");
    }

    @Test
    void rejectedUpgrade() {
        run("HTTP/1.1 200 OK\r\n"
            + "Content-Length: 5\r\n"
            + "\r\n"
            + "hello");
    }

    @Test
    void unexpectedUpgradeProtocol() {
        run("HTTP/1.1 101 Switching Protocols\r\n"
            + "Connection: Upgrade\r\n"
            + "Upgrade: websocket\r\n"
            + "\r\n");
    }

    @Test
    void oversizedUpgradeResponse() {
        run("HTTP/1.1 101 Switching Protocols\r\n"
            + "Connection: Upgrade\r\n"
            + "Upgrade: h2c\r\n"
            + "Content-Length: 6101\r\n"
            + "\r\n"
            + "abc");
    }

    @Test
    void invalidHttp2Frame() {
        run("HTTP/1.1 101 Switching Protocols\r\n"
            + "Connection: Upgrade\r\n"
            + "Upgrade: h2c\r\n"
            + "\r\n"
            + "SEP"
            // SETTINGS frame with a length that is not a multiple of 6
            + "\0\0\1\4\0\0\0\0\0\0");
    }

    @Test
    void sameInstanceTwice() {
        HttpClientUpgradeHandlerFuzzer fuzzer = new HttpClientUpgradeHandlerFuzzer();
        fuzzer.test(provider("HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nContent-Length: 6101\r\n\r\n"));
        fuzzer.test(provider("HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n"));
    }

    private static void run(String input) {
        HttpClientUpgradeHandlerFuzzer.fuzzerTestOneInput(provider(input));
    }

    private static CannedFuzzedDataProvider provider(String input) {
        return CannedFuzzedDataProvider.create(List.<Object>of(input.getBytes(StandardCharsets.ISO_8859_1)));
    }
}

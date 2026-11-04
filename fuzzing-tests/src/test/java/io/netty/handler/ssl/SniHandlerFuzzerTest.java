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
package io.netty.handler.ssl;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import io.netty.handler.codec.DecoderException;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.net.IDN;
import java.util.List;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SniHandlerFuzzerTest {
    @Test
    void selectsContextForHostName() {
        run(clientHello(ascii("www.netty.io")));
        run(clientHello(ascii("www.example.com")));
    }

    @Test
    void ignoresHostNameRejectedByIdn() {
        // the non-ASCII byte decodes to U+FFFD, so DomainNameMapping passes the name to IDN.toASCII, which
        // rejects the empty first label
        run(clientHello(new byte[] {'.', (byte) 0xFF}));
    }

    @Test
    void reportsUnexpectedExceptions() {
        SniHandlerFuzzer fuzzer = new SniHandlerFuzzer(0);
        assertThrows(DecoderException.class, () -> fuzzer.onException(
            new DecoderException(new IllegalArgumentException())));
        IllegalArgumentException idnException = assertThrows(IllegalArgumentException.class,
            () -> IDN.toASCII(".�", IDN.ALLOW_UNASSIGNED));
        // thrown by IDN, but not from the SNI lookup
        assertThrows(DecoderException.class, () -> fuzzer.onException(new DecoderException(idnException)));
    }

    private static void run(byte[] input) {
        SniHandlerFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(8192, input)));
    }

    /**
     * Creates a TLS 1.2 ClientHello record with a server_name extension.
     */
    private static byte[] clientHello(byte[] hostName) {
        ByteArrayOutputStream serverName = new ByteArrayOutputStream();
        writeShort(serverName, hostName.length + 3); // server_name_list length
        serverName.write(0); // host_name
        writeShort(serverName, hostName.length);
        serverName.writeBytes(hostName);

        ByteArrayOutputStream extensions = new ByteArrayOutputStream();
        writeShort(extensions, 0); // server_name
        writeShort(extensions, serverName.size());
        extensions.writeBytes(serverName.toByteArray());

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        writeShort(body, 0x0303); // client_version
        body.writeBytes(new byte[32]); // random
        body.write(0); // session_id
        writeShort(body, 2);
        writeShort(body, 0x002F); // TLS_RSA_WITH_AES_128_CBC_SHA
        body.write(1);
        body.write(0); // null compression
        writeShort(body, extensions.size());
        body.writeBytes(extensions.toByteArray());

        ByteArrayOutputStream record = new ByteArrayOutputStream();
        record.write(0x16); // handshake
        writeShort(record, 0x0301);
        writeShort(record, body.size() + 4);
        record.write(1); // client_hello
        record.write(body.size() >> 16);
        writeShort(record, body.size());
        record.writeBytes(body.toByteArray());
        return record.toByteArray();
    }

    private static void writeShort(ByteArrayOutputStream out, int value) {
        out.write(value >> 8);
        out.write(value);
    }

    private static byte[] ascii(String s) {
        return s.getBytes(US_ASCII);
    }
}

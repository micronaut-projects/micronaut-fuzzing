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

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.exceptions.HttpStatusException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;

class MultipartTargetTest {
    @Test
    void field() {
        MultipartTarget.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            "boundary", 1, true, "field", false, true, "value"
        )));
    }

    @Test
    void files() {
        MultipartTarget.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            "boundary", 2,
            true, "file", true, "a.txt", "", 2, false, "content",
            true, "file2", true, "b.bin", "application/x-custom", 3, true, "content2"
        )));
    }

    @Test
    void malformedPart() {
        // the decoder refuses the transfer encoding
        MultipartTarget.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            "boundary", 1, true, "field\"\r\nContent-Transfer-Encoding: foo\r\nX-Foo: \"", false, true, "value"
        )));
    }

    @Test
    void invalidContentType() {
        MultipartTarget.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            "boundary", 1, true, "file", true, "a.txt", "-", 3, true, "content"
        )));
    }

    @Test
    void invalidContentLength() {
        MultipartTarget.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            "boundary", 1, true, "field\"\r\nContent-Length: x\r\nX-Foo: \"", false, true, "value"
        )));
    }

    @Test
    void otherIllegalArgument() {
        assertFalse(MultipartTarget.isThrownByHeaderParsing(new IllegalArgumentException(), "io.micronaut.http.MediaType", "of"));
    }

    @Test
    void endsBeforeClosingBoundary() {
        MultipartTarget.decode("boundary", "--boundary\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue".getBytes(StandardCharsets.ISO_8859_1));
    }

    @Test
    void otherBadRequest() {
        assertFalse(MultipartTarget.isMalformedBody(new HttpStatusException(HttpStatus.BAD_REQUEST, "foo")));
        assertFalse(MultipartTarget.isMalformedBody(new HttpStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "foo")));
        HttpStatusException withOtherCause = new HttpStatusException(HttpStatus.BAD_REQUEST, "foo");
        withOtherCause.initCause(new IllegalStateException());
        assertFalse(MultipartTarget.isMalformedBody(withOtherCause));
    }
}

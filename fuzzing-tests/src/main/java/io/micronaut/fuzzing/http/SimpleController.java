/*
 * Copyright 2017-2024 original authors
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

import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;

@Singleton
@Controller
public final class SimpleController {
    static final String ECHO_PUBLISHER = "/echo-publisher";
    static final String ECHO_ARRAY = "/echo-array";
    static final String ECHO_STRING = "/echo-string";
    static final String ECHO_PIECE_JSON = "/echo-piece-json";

    @Get
    public String index() {
        return "index";
    }

    @Post(ECHO_PUBLISHER)
    public Publisher<byte[]> echo(@Body Publisher<byte[]> foo) {
        return foo;
    }

    @Post(ECHO_ARRAY)
    public byte[] echo(@Body byte[] foo) {
        return foo;
    }

    @Post(ECHO_STRING)
    public String echo(@Body String foo) {
        return foo;
    }

    @Post(ECHO_PIECE_JSON)
    @Consumes({
        MediaType.APPLICATION_JSON,
        MediaType.APPLICATION_FORM_URLENCODED
    })
    public String echoPieceJson(@Body("foo") String foo) {
        return foo;
    }
}

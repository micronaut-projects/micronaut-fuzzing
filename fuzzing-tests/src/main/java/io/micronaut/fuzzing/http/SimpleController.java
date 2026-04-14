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
import io.micronaut.http.annotation.Header;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.annotation.QueryValue;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;

import java.util.List;

@Singleton
@Controller
public final class SimpleController {
    static final String ECHO_PUBLISHER = "/echo-publisher";
    static final String ECHO_ARRAY = "/echo-array";
    static final String ECHO_STRING = "/echo-string";
    static final String ECHO_PIECE_JSON = "/echo-piece-json";
    static final String ECHO_QUERY = "/echo-query";
    static final String ECHO_PATH = "/echo-path";
    static final String ECHO_HEADER = "/echo-header";
    static final String ECHO_FORM = "/echo-form";
    static final String ECHO_FORM_PAIR = "/echo-form-pair";
    static final String ECHO_AUTHORS = "/echo-authors";

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
    @Get(ECHO_QUERY + "{?foo}")
    public String echoQuery(@QueryValue String foo) {
        return foo;
    }

    @Get(ECHO_PATH + "/{foo}")
    public String echoPath(@PathVariable String foo) {
        return foo;
    }

    @Get(ECHO_HEADER)
    public String echoHeader(@Header("X-Foo") String foo) {
        return foo;
    }

    @Post(ECHO_FORM)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String echoForm(@Body("foo") String foo) {
        return foo;
    }

    @Post(ECHO_FORM_PAIR)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String echoFormPair(@Body("foo") String foo, @Body("bar") String bar) {
        return foo + ":" + bar;
    }
    @Post(ECHO_AUTHORS)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String echoAuthors(@Body AuthorForm form) {
        List<AuthorEntry> authors = form.getAuthors();
        return authors == null ? "empty" : "count:" + authors.size();
    }
}

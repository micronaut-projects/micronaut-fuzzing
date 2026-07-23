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

import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.CookieValue;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.annotation.Part;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.annotation.QueryValue;
import io.micronaut.http.annotation.RequestBean;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.multipart.CompletedFileUpload;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Optional;

import static io.micronaut.http.MediaType.MULTIPART_FORM_DATA;

/**
 * Simple HTTP endpoints used by fuzzing tests.
 */
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
    static final String UPLOAD_FILE = "/upload-file";
    static final String UPLOAD_FIELDS = "/upload-fields";
    static final String UPLOAD_MIXED = "/upload-mixed";
    static final String ECHO_BEAN = "/echo-bean";
    static final String ECHO_REQUEST_BEAN = "/echo-request-bean";
    static final String ECHO_COOKIE = "/echo-cookie";
    static final String UPLOAD_MULTIPLE = "/upload-multiple";
    static final String ECHO_REGEX_ID      = "/users";
    static final String ECHO_REGEX_SLUG    = "/items";
    static final String ECHO_REGEX_VERSION = "/api";
    static final String ECHO_REGEX_UUID    = "/resource";
    static final String ECHO_MULTI_VAR     = "/users";
    static final String ECHO_EXT           = "/files";
    static final String ECHO_WILDCARD      = "/docs";
    static final String ECHO_OPTIONAL      = "/search";
    static final String ECHO_NEGOTIATED = "/echo-negotiated";
    static final String ECHO_MULTI_ACCEPT = "/echo-multi-accept";
    static final String ECHO_QUERY_POJO = "/echo-query-pojo";
    static final String ECHO_STATUS       = "/echo-status/";
    static final String ECHO_OPTIONAL_ID = "/echo-optional-id";
    static final String ECHO_STREAM = "/echo-stream";
    static final String ECHO_SET_COOKIE = "/echo-set-cookie";
    static final String ECHO_MULTI_QUERY = "/echo-multi-query";
    static final String ECHO_JSON_OBJECT = "/echo-json-object";

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

    @Post(value = UPLOAD_FILE, consumes = MULTIPART_FORM_DATA)
    public String uploadFile(@Part("file") CompletedFileUpload file) {
        return "size:" + file.getSize();
    }

    @Post(value = UPLOAD_FIELDS, consumes = MULTIPART_FORM_DATA)
    public String uploadFields(@Part("username") String username,
                                @Part("email") String email) {
        return username + "/" + email;
    }

    @Post(value = UPLOAD_MIXED, consumes = MULTIPART_FORM_DATA)
    public String uploadMixed(@Part("name") String name,
                              @Part("data") CompletedFileUpload data) {
        return name + ":" + data.getSize();
    }

    @Get(ECHO_BEAN + "{?keyword,page,active}")
    public String echoBean(SearchQuery query) {
        return query.getKeyword() + ":"
            + query.getPage() + ":"
            + query.getActive();
    }

    @Get(ECHO_REQUEST_BEAN + "/{id}{?filter}")
    public String echoRequestBean(@RequestBean RequestData data) {
        return data.getId() + ":"
            + data.getFilter() + ":"
            + data.getVersion();
    }

    @Get(ECHO_COOKIE)
    public String echoCookie(@CookieValue("session") @Nullable String session,
                             @CookieValue("theme") @Nullable String theme) {
        return session + ":" + theme;
    }

    @Post(value = UPLOAD_MULTIPLE, consumes = MULTIPART_FORM_DATA)
    public String uploadMultiple(@Part("files") CompletedFileUpload[] files) {
        return "count:" + files.length;
    }

    @Get(ECHO_EXT + "/{name}.{ext}")
    public String echoExt(@PathVariable String name, @PathVariable String ext) {
        return name + "." + ext;
    }

    @Get(ECHO_REGEX_ID + "/{id:[0-9]+}")
    public String echoRegexId(@PathVariable String id) {
        return "user:" + id;
    }

    @Get(ECHO_REGEX_SLUG + "/{slug:[a-z\\-]+}")
    public String echoRegexSlug(@PathVariable String slug) {
        return "item:" + slug;
    }

    @Get(ECHO_REGEX_VERSION + "/{version:v[0-9]+}")
    public String echoRegexVersion(@PathVariable String version) {
        return "version:" + version;
    }

    @Get(ECHO_REGEX_UUID + "/{uuid:[0-9a-f\\-]+}")
    public String echoRegexUuid(@PathVariable String uuid) {
        return "uuid:" + uuid;
    }

    @Get(ECHO_MULTI_VAR + "/{userId:[0-9]+}/posts/{postId:[0-9]+}")
    public String echoMultiVar(@PathVariable String userId, @PathVariable String postId) {
        return "user:" + userId + "/post:" + postId;
    }

    @Get(ECHO_WILDCARD + "/{+path}")
    public String echoWildcard(@PathVariable String path) {
        return "docs:" + path;
    }

    @Get(ECHO_OPTIONAL + "{/category}")
    public String echoOptional(@PathVariable @Nullable String category) {
        return "search:" + category;
    }

    @Get(ECHO_NEGOTIATED)
    @Produces({MediaType.APPLICATION_JSON, MediaType.TEXT_PLAIN})
    public String echoNegotiated(@QueryValue @Nullable String value) {
        return value != null ? value : "empty";
    }

    @Post(ECHO_MULTI_ACCEPT)
    @Consumes({MediaType.APPLICATION_JSON, MediaType.APPLICATION_FORM_URLENCODED})
    @Produces({MediaType.APPLICATION_JSON, MediaType.TEXT_PLAIN})
    public HttpResponse<String> echoMultiAccept(@Body @Nullable String body) {
        return HttpResponse.ok(body != null ? body : "empty");
    }

    @Get(ECHO_QUERY_POJO + "{?name,minAge}")
    public String echoQueryPojo(@QueryValue FilterParams params) {
        return params.getName() + ":" + params.getMinAge();
    }

    @Get(ECHO_STATUS + "{status}")
    public String echoStatus(@PathVariable Status status) {
        return status.name();
    }

    @Get(ECHO_OPTIONAL_ID + "{?id}")
    public String echoOptionalId(@QueryValue Optional<Integer> id) {
        return id.map(String::valueOf).orElse("none");
    }

    @Post(ECHO_STREAM)
    @Consumes(MediaType.APPLICATION_OCTET_STREAM)
    public String echoStream(@Body InputStream body) throws IOException {
        return "bytes:" + body.readAllBytes().length;
    }

    @Get(ECHO_SET_COOKIE + "{?value}")
    public HttpResponse<String> echoSetCookie(@QueryValue @Nullable String value) {
        return HttpResponse.<String>ok("ok")
            .cookie(Cookie.of("fuzz-cookie", value != null ? value : "default"));
    }

    @Get(ECHO_MULTI_QUERY)
    public String echoMultiQuery(@QueryValue @Nullable List<String> tag) {
        return tag == null ? "none" : String.join(",", tag);
    }

    @Post(ECHO_JSON_OBJECT)
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public SearchQuery echoJsonObject(@Body SearchQuery query) {
        return query;
    }
}

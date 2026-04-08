/*
 * Copyright 2017-2025 original authors
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
import io.micronaut.context.ApplicationContext;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.web.router.Router;
import io.micronaut.web.router.UriRouteMatch;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

@FuzzTarget
@HttpDict
@Dict({
    // All paths from SimpleController
    SimpleController.ECHO_PUBLISHER,
    SimpleController.ECHO_ARRAY,
    SimpleController.ECHO_STRING,
    SimpleController.ECHO_PIECE_JSON,
    SimpleController.ECHO_QUERY,
    SimpleController.ECHO_PATH,
    SimpleController.ECHO_HEADER,
    SimpleController.ECHO_FORM,
    SimpleController.ECHO_FORM_PAIR,
    SimpleController.UPLOAD_FILE,
    SimpleController.UPLOAD_FIELDS,
    SimpleController.UPLOAD_MIXED,
    SimpleController.ECHO_BEAN,
    SimpleController.ECHO_REQUEST_BEAN,
    SimpleController.ECHO_COOKIE,
    SimpleController.UPLOAD_MULTIPLE,
    SimpleController.ECHO_NEGOTIATED,
    SimpleController.ECHO_MULTI_ACCEPT,

    // Path traversal attempts
    "/", "/../", "/./", "//", "/%2e%2e/",
    "/echo-path/../echo-string",
    "/echo-path/./test",

    // Query strings
    "?foo=bar", "?foo=bar&baz=qux",
    "?foo=", "?=bar", "?foo",
    "?foo=bar&foo=baz",

    // Variable values
    "/echo-path/test", "/echo-path/hello%20world",
    "/echo-path/%00", "/echo-path/../../etc/passwd",

    // Encoding edge cases
    "%2F", "%00", "%20", "%25", "%0A", "%0D",
    "/%2e%2e/%2e%2e/etc/passwd",

    // Unusual characters in paths
    "\u0000", " ", "\t", "\n", "\r",
    "/echo-path/<script>", "/echo-path/{{id}}",

    // Long paths
    "/a/b/c/d/e/f/g/h/i/j",
})
public class UriRouterFuzzTarget {
    private static final Router ROUTER;

    static {
        ApplicationContext ctx = ApplicationContext.run(Map.of());
        ROUTER = ctx.getBean(Router.class);
    }

    private static final HttpMethod[] HTTP_METHODS = {
        HttpMethod.GET,
        HttpMethod.POST,
        HttpMethod.PUT,
        HttpMethod.DELETE,
        HttpMethod.PATCH,
        HttpMethod.HEAD,
        HttpMethod.OPTIONS,
    };

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        int scenario = data.consumeInt(0, 3);

        switch (scenario) {
            case 0 -> fuzzFindRoute(data);
            case 1 -> fuzzFindAny(data);
            case 2 -> fuzzFindAllClosest(data);
            case 3 -> fuzzFindWithRequest(data);
        }
    }

    private static void fuzzFindRoute(FuzzedDataProvider data) {
        HttpMethod method = data.pickValue(HTTP_METHODS);
        String uri = data.consumeRemainingAsString();

        try (Stream<UriRouteMatch<Object, Object>> stream = ROUTER.find(method, uri, null)) {
            stream.forEach(match -> {
                match.getVariableValues();
                match.getUri();
            });
        }
    }

    private static void fuzzFindAny(FuzzedDataProvider data) {
        String uri = data.consumeRemainingAsString();

        try (Stream<UriRouteMatch<Object, Object>> stream = ROUTER.findAny(uri, null)) {
            stream.forEach(match -> {
                match.getVariableValues();
                match.getUri();
            });
        }
    }


    private static void fuzzFindAllClosest(FuzzedDataProvider data) {
        HttpMethod method = data.pickValue(HTTP_METHODS);
        String uri = data.consumeRemainingAsString();

        try {
            HttpRequest<?> request = HttpRequest.create(method, uri);
            List<UriRouteMatch<Object, Object>> matches = ROUTER.findAllClosest(request);
            for (UriRouteMatch<?, ?> match : matches) {
                match.getVariableValues();
                match.getUri();
            }
        } catch (IllegalArgumentException | NullPointerException ignored) {
        }
    }

    private static void fuzzFindWithRequest(FuzzedDataProvider data) {
        HttpMethod method = data.pickValue(HTTP_METHODS);
        String uri = data.consumeRemainingAsString();

        try {
            HttpRequest<?> request = HttpRequest.create(method, uri);
            try (Stream<UriRouteMatch<Object, Object>> stream = ROUTER.find(request)) {
                stream.forEach(match -> {
                    match.getVariableValues();
                    match.getUri();
                });
            }
        } catch (IllegalArgumentException | NullPointerException ignored) {
        }
    }

    static void main(String[] args) {
        var runner = LocalJazzerRunner.create(UriRouterFuzzTarget.class);
        if (args.length > 0) {
            runner.reproduce(Path.of(args[0]));
        } else {
            runner.fuzz();
        }
    }
}

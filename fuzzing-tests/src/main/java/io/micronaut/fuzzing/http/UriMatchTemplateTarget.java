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
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.http.uri.UriMatchTemplate;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
@Dict({
    "{", "}", "{?", "{+", "{#", "{/", "{.", "{&",
    "*", ":", ",", "/", "/users/", "/api/",
    "{id}", "{id*}", "{id:3}", "{?q,limit}",
    "%2F", "%00", "//", "/../",
})
public class UriMatchTemplateTarget {

    private static final String[] NEST_SUFFIXES = {
        "/{id}",
        "/{name}{?filter}",
        "/details",
        "{?page,size}",
    };

    private static final UriMatchTemplate[] FIXED_TEMPLATES;

    static {
        FIXED_TEMPLATES = new UriMatchTemplate[]{
            new UriMatchTemplate(SimpleController.ECHO_PATH + "/{foo}"),
            new UriMatchTemplate("/echo-query{?foo}"),
            new UriMatchTemplate("/echo-request-bean/{id}{?filter}"),
            new UriMatchTemplate("/users/{userId}/orders/{orderId}"),
            new UriMatchTemplate("/files{+path}"),
            new UriMatchTemplate("/browse{/folder}"),
            new UriMatchTemplate("/search{?q*}"),
        };
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        int scenario = data.consumeInt(0, 3);

        switch (scenario) {
            case 0 -> {
                UriMatchTemplate t = data.pickValue(FIXED_TEMPLATES);
                String path = data.consumeRemainingAsString();
                t.match(path).ifPresent(info -> info.getVariableValues());
            }
            case 1 -> {
                String path = data.consumeRemainingAsString();
                for (UriMatchTemplate t : FIXED_TEMPLATES) {
                    t.match(path).ifPresent(info -> info.getVariableValues());
                }
            }
            case 2 -> {
                UriMatchTemplate t = data.pickValue(FIXED_TEMPLATES);
                String path = data.consumeString(200);
                String query = data.consumeRemainingAsString();
                t.match(path + "?" + query).ifPresent(info -> info.getVariableValues());
            }
            case 3 -> {
                UriMatchTemplate t = data.pickValue(FIXED_TEMPLATES);
                String suffix = data.pickValue(NEST_SUFFIXES);
                String path = data.consumeRemainingAsString();
                UriMatchTemplate nested = (UriMatchTemplate) t.nest(suffix);
                nested.match(path).ifPresent(info -> info.getVariableValues());
                nested.toPathString();
                nested.getVariableNames();
                nested.getVariables();
            }
            default -> throw new IllegalStateException("Unexpected scenario: " + scenario);
        }
    }
}


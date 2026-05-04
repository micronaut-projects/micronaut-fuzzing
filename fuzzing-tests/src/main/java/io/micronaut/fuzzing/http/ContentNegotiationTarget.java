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
import io.micronaut.http.MediaType;

import java.util.List;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
@Dict({

    SimpleController.ECHO_NEGOTIATED,
    SimpleController.ECHO_MULTI_ACCEPT,


    "Accept: application/json",
    "Accept: text/plain",
    "Accept: text/xml",
    "Accept: */*",
    "Accept: application/json;q=0.9,text/plain;q=0.8",

    "Accept: application/json;q=999",
    "Accept: application/json;q=-1",
    "Accept: a/b/c/d",
    "Accept: ",


    "Content-Type: application/json",
    "Content-Type: application/json; charset=utf-8",
    "Content-Type: ",
    "Content-Type: a/b/c",
    "Content-Type: application/json; charset=",


    "q=0.9", "q=1.0", "q=0", "q=",
})
public class ContentNegotiationTarget {

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        int scenario = data.consumeInt(0, 3);

        if (scenario == 0) {
            String accept = data.pickValue(new String[]{
                "application/json",
                "text/plain",
                "*/*",
                "application/json;q=0.9,text/plain;q=0.8",
                "application/json;q=999",
                "application/json;q=-1",
                "a/b/c/d",
                "",
                data.consumeString(100)
            });
            MediaType.orderedOf(List.of(accept));

        } else if (scenario == 1) {
            String contentType = data.pickValue(new String[]{
                "application/json",
                "application/json; charset=utf-8",
                "application/x-www-form-urlencoded",
                "",
                "a/b/c",
                "application/json; q=abc",
                data.consumeString(80)
            });
            try {
                MediaType.of(contentType);
            } catch (IllegalArgumentException ignored) {
            }

        } else if (scenario == 2) {
            String accept = data.consumeString(100);
            String contentType = data.consumeString(80);
            List<MediaType> accepted = MediaType.orderedOf(List.of(accept));
            try {
                MediaType ct = MediaType.of(contentType);
                for (MediaType a : accepted) {
                    a.matches(ct);
                }
            } catch (IllegalArgumentException ignored) {
            }

        } else {
            int count = data.consumeInt(5, 50);
            StringBuilder accept = new StringBuilder();
            for (int i = 0; i < count; i++) {
                if (i > 0) {
                    accept.append(",");
                }
                accept.append(data.consumeString(20));
                accept.append(";q=");
                accept.append(data.consumeString(5));
            }
            MediaType.orderedOf(List.of(accept.toString()));
        }
    }
}

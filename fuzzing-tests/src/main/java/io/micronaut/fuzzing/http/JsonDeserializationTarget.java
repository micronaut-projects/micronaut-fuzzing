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
import io.micronaut.context.ApplicationContext;
import io.micronaut.core.type.Argument;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.micronaut.json.JsonMapper;
import tools.jackson.core.JacksonException;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Fuzz target for JSON deserialization via Micronaut's JsonMapper.
 */
@FuzzTarget
@Dict({
    "{", "}", "[", "]", ":", ",", "\"",

    "null", "true", "false",

    "\"keyword\":", "\"page\":", "\"active\":",

    "{}", "[]", "\"\"",
    "{\"keyword\":\"test\",\"page\":1,\"active\":true}",

    "{\"a\":", "[[[[", "]]]]", "}}}}",

    "999999999999999999999999999999",
    "-999999999999999999999999999999",
    "1e9999",
    "1.0e-9999",

    "\"\\u0000\"",
    "\"\\n\\r\\t\"",
    "\"\\uD800\\uDFFF\"",

    "{\"a\":1,\"a\":2}",

    "{}garbage",
    "[]extra",
})
public class JsonDeserializationTarget {

    private static final JsonMapper JSON_MAPPER;

    static {
        JSON_MAPPER = ApplicationContext.run(Map.of()).getBean(JsonMapper.class);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
        byte[] raw = data.consumeRemainingAsBytes();
        int scenario = raw.length > 0 ? (raw[0] & 0xFF) % 3 : 0;
        byte[] json = raw.length > 1 ? Arrays.copyOfRange(raw, 1, raw.length) : new byte[0];

        switch (scenario) {
            case 0 -> deserializeToMap(json);
            case 1 -> deserializeToPojo(json);
            case 2 -> deserializeToList(json);
            default -> {
            }
        }
    }

    private static void deserializeToMap(byte[] json) {
        try {
            Map<?, ?> map = JSON_MAPPER.readValue(json, Argument.mapOf(String.class, Object.class));
            if (map != null) {
                map.values().forEach(v -> {
                    if (v != null) {
                        v.toString();
                    }
                });
            }
        } catch (IOException | IllegalArgumentException | JacksonException ignored) {
            ignoreInvalidInput(ignored);
        }
    }

    private static void deserializeToPojo(byte[] json) {
        try {
            SearchQuery q = JSON_MAPPER.readValue(json, Argument.of(SearchQuery.class));
            if (q != null) {
                JSON_MAPPER.writeValueAsBytes(q);
            }
        } catch (IOException | IllegalArgumentException | JacksonException ignored) {
            ignoreInvalidInput(ignored);
        }
    }

    private static void deserializeToList(byte[] json) {
        try {
            List<?> list = JSON_MAPPER.readValue(json, Argument.listOf(Object.class));
            if (list != null) {
                list.forEach(v -> {
                    if (v != null) {
                        v.toString();
                    }
                });
            }
        } catch (IOException | IllegalArgumentException | JacksonException ignored) {
            ignoreInvalidInput(ignored);
        }
    }

    private static void ignoreInvalidInput(Exception exception) {
        // Malformed JSON and unsupported JSON-to-type mappings are expected fuzz inputs.
        exception.getClass();
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(JsonDeserializationTarget.class).fuzz();
    }
}

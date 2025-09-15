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
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;

import java.util.Map;

@FuzzTarget
public class EmbeddedHttp2Target extends EmbeddedHttpTarget {
    private static final EmbeddedHttpTarget.ContextHolder HTTP2 = new EmbeddedHttpTarget.ContextHolder(Map.of("micronaut.server.http-version", "2.0"));

    EmbeddedHttp2Target(ContextHolder contextHolder) {
        super(contextHolder);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider input) {
        new EmbeddedHttp2Target(HTTP2).test(input);
    }

    static void main(String[] args) {
        LocalJazzerRunner.create(EmbeddedHttp2Target.class).fuzz();
    }
}

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

import io.micronaut.context.BeanProvider;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.server.HttpServerConfiguration;
import io.micronaut.http.server.util.DefaultHttpHostResolver;
import io.micronaut.runtime.server.EmbeddedServer;
import jakarta.inject.Singleton;

/**
 * Fuzzing support type.
 */
@Singleton
@Replaces(DefaultHttpHostResolver.class)
public class StableHttpHostResolver extends DefaultHttpHostResolver {
    private static final boolean LOCAL = false;

    public StableHttpHostResolver(HttpServerConfiguration serverConfiguration, @Nullable BeanProvider<EmbeddedServer> embeddedServer) {
        super(serverConfiguration, embeddedServer);
    }

    @Override
    protected String getEmbeddedHost() {
        return LOCAL ? "http://localhost:8080" : "http://example.com:8080";
    }
}

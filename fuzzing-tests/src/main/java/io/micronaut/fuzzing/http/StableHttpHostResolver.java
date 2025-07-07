package io.micronaut.fuzzing.http;

import io.micronaut.context.BeanProvider;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.server.HttpServerConfiguration;
import io.micronaut.http.server.util.DefaultHttpHostResolver;
import io.micronaut.runtime.server.EmbeddedServer;
import jakarta.inject.Singleton;

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

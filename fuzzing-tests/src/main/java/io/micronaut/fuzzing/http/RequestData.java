package io.micronaut.fuzzing.http;

import io.micronaut.core.annotation.Introspected;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.annotation.QueryValue;

@Introspected
public class RequestData {
    @PathVariable
    private String id;

    @Nullable
    @QueryValue
    private String filter;

    @Nullable
    @Header("X-Version")
    private String version;

    @NonNull
    public String getId() {
        return id;
    }

    public void setId(@NonNull String id) {
        this.id = id;
    }

    @Nullable
    public String getFilter() {
        return filter;
    }

    public void setFilter(@Nullable String filter) {
        this.filter = filter;
    }

    @Nullable
    public String getVersion() {
        return version;
    }

    public void setVersion(@Nullable String version) {
        this.version = version;
    }
}

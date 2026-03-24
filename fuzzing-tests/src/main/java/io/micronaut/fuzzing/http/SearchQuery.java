package io.micronaut.fuzzing.http;

import io.micronaut.core.annotation.Introspected;
import io.micronaut.core.annotation.Nullable;

@Introspected
public class SearchQuery {
    @Nullable
    private String keyword;

    @Nullable
    private Integer page;

    @Nullable
    private Boolean active;

    @Nullable
    public String getKeyword() {
        return keyword;
    }

    public void setKeyword(@Nullable String keyword) {
        this.keyword = keyword;
    }

    @Nullable
    public Integer getPage() {
        return page;
    }

    public void setPage(@Nullable Integer page) {
        this.page = page;
    }

    @Nullable
    public Boolean getActive() {
        return active;
    }

    public void setActive(@Nullable Boolean active) {
        this.active = active;
    }
}

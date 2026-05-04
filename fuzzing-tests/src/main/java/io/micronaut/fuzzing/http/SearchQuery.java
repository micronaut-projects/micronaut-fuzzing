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

import io.micronaut.core.annotation.Introspected;
import io.micronaut.core.annotation.Nullable;

/**
 * Fuzzing support type.
 */
@Introspected
public final class SearchQuery {
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

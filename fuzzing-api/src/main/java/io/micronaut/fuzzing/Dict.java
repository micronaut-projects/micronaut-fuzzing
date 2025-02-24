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
package io.micronaut.fuzzing;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Add fuzzing dictionary entries to a {@link FuzzTarget}.
 * <p>Can also be used as a meta-annotation. E.g. adding the {@link HttpDict} annotation will add a
 * dictionary with HTTP-related entries.
 *
 * @see DictResource
 */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.TYPE)
@Repeatable(Dict.Repeated.class)
@Inherited
public @interface Dict {
    /**
     * @return The statically defined dictionary entries
     */
    String[] value();

    @Retention(RetentionPolicy.CLASS)
    @Target(ElementType.TYPE)
    @Inherited
    @interface Repeated {
        Dict[] value();
    }
}

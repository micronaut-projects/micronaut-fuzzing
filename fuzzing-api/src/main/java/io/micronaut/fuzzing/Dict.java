package io.micronaut.fuzzing;

import java.lang.annotation.ElementType;
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
public @interface Dict {
    /**
     * @return The statically defined dictionary entries
     */
    String[] value();

    @Retention(RetentionPolicy.CLASS)
    @Target(ElementType.TYPE)
    @interface Repeated {
        Dict[] value();
    }
}

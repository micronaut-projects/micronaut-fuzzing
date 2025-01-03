package io.micronaut.fuzzing;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Mark a fuzz target. This target must have a {@code fuzzerTestOneInput} method.
 * <p>It is highly recommended to also declare a {@link Dict dictionary}.
 */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.TYPE)
public @interface FuzzTarget {
    /**
     * Enable this target implicitly. {@code true} by default.
     * <p>This is useful so that all targets run on oss-fuzz by default, but you can still disable
     * this for some select targets that should only run when invoked explicitly using the jazzer
     * gradle task.
     *
     * @return Whether this target should be enabled implicitly
     */
    boolean enableImplicitly() default true;
}

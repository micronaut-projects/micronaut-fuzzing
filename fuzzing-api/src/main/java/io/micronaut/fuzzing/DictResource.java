package io.micronaut.fuzzing;

import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Add a dictionary from a classpath resource.
 *
 * @see Dict
 */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.TYPE)
@Repeatable(DictResource.Repeated.class)
public @interface DictResource {
    /**
     * @return The resource path
     */
    String value();

    @Retention(RetentionPolicy.CLASS)
    @Target(ElementType.TYPE)
    @interface Repeated {
        DictResource[] value();
    }
}

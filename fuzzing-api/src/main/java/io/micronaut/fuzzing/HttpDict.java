package io.micronaut.fuzzing;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Add a dictionary with HTTP-related values.
 */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.TYPE)
@DictResource("dictionaries/http.dict")
public @interface HttpDict {
}

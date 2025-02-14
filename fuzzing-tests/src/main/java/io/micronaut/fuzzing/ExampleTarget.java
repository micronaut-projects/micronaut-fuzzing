package io.micronaut.fuzzing;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;

import java.nio.file.Path;

@FuzzTarget
public class ExampleTarget {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        Ingredient ingredient;
        try {
            ingredient = new Ingredient(
                data.consumeString(10),
                data.consumeInt(),
                data.consumeInt()
            );
        } catch (IllegalArgumentException e) {
            return;
        }
        ingredient.pricePerKg();
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(ExampleTarget.class).reproduce(Path.of("/"));
    }

    record Ingredient(
        String name,
        int massInGrams,
        int priceInCents
    ) {

        Ingredient {
            if (massInGrams <= 0) {
                throw new IllegalArgumentException("Mass must be greater than 0");
            }
        }

        int pricePerKg() {
            return priceInCents * 1000 / massInGrams;
        }
    }

    /*
    @Test
    void test() {
        assertEquals(50, new Ingredient("flour", 2000, 100).pricePerKg());
    }
     */
}

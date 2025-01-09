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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;

/**
 * Docs example.
 */
@FuzzTarget(enableImplicitly = false)
public class IngredientTarget {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        Ingredient ingredient;
        try {
            ingredient = new Ingredient(data.consumeString(10), data.consumeInt(), data.consumeInt());
        } catch (IllegalArgumentException ok) {
            return;
        }
        if (ingredient.pricePerKg() <= 0) {
            throw new AssertionError();
        }
    }

    record Ingredient(
        String name,
        int massInGrams,
        int priceInCents
    ) {
        Ingredient {
            if (massInGrams == 0) {
                throw new IllegalArgumentException("Mass cannot be 0");
            }
        }

        int pricePerKg() {
            return priceInCents * 1000 / massInGrams;
        }
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(IngredientTarget.class).fuzz();
    }
}

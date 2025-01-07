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
package io.micronaut.fuzzing.processor;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micronaut.core.annotation.AnnotationValue;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.DictResource;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.inject.ast.ClassElement;
import io.micronaut.inject.visitor.TypeElementVisitor;
import io.micronaut.inject.visitor.VisitorContext;
import io.micronaut.inject.writer.GeneratedFile;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Internal
public class FuzzTargetVisitor implements TypeElementVisitor<FuzzTarget, FuzzTarget> {
    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public void visitClass(ClassElement element, VisitorContext context) {
        List<DefinedFuzzTarget> targets = new ArrayList<>();
        if (element.hasStereotype(FuzzTarget.class)) {
            if (element.findMethod("fuzzerTestOneInput").isEmpty()) {
                context.fail("Class-level FuzzTarget is missing fuzzerTestOneInput method", element);
                return;
            }

            List<String> manualDict = new ArrayList<>();
            for (AnnotationValue<Dict> value : element.getAnnotationValuesByType(Dict.class)) {
                manualDict.addAll(Arrays.asList(value.stringValues()));
            }
            List<String> dictResources = new ArrayList<>();
            for (AnnotationValue<DictResource> value : element.getAnnotationValuesByType(DictResource.class)) {
                dictResources.add(value.stringValue().get());
            }

            if (manualDict.isEmpty() && dictResources.isEmpty()) {
                context.warn("No dictionary defined for fuzz target. Fuzzing may be inefficient!", element);
            }
            targets.add(new DefinedFuzzTarget(
                element.getName(),
                manualDict.isEmpty() ? null : manualDict,
                dictResources.isEmpty() ? null : dictResources,
                element.booleanValue(FuzzTarget.class, "enableImplicitly").orElse(true)
            ));
        }
        if (!targets.isEmpty()) {
            Optional<GeneratedFile> output = context.visitMetaInfFile(DefinedFuzzTarget.DIRECTORY + "/" + element.getName() + ".json", element);
            if (output.isPresent()) {
                try (OutputStream os = output.get().openOutputStream()) {
                    mapper.writeValue(os, targets);
                } catch (IOException e) {
                    context.fail("Failed to write fuzz target metadata: " + e.getMessage(), element);
                }
            }
        }
    }

    @Override
    public @NonNull VisitorKind getVisitorKind() {
        return VisitorKind.ISOLATING;
    }
}

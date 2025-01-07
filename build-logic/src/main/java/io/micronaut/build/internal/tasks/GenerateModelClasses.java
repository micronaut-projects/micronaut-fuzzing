/*
 * Copyright 2003-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.build.internal.tasks;

import org.gradle.api.DefaultTask;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.OutputDirectory;
import org.gradle.api.tasks.TaskAction;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;

public abstract class GenerateModelClasses extends DefaultTask {
    @OutputDirectory
    public abstract DirectoryProperty getOutputDirectory();

    @Input
    public abstract Property<String> getPackageName();

    @TaskAction
    public void generateModelClasses() throws IOException {
        var packageName = getPackageName().get();
        var packageDir =
            getOutputDirectory().get().getAsFile().toPath().resolve(packageName.replace('.', '/'));
        Files.createDirectories(packageDir);
        var model = packageDir.resolve("DefinedFuzzTarget.java");
        try (var writer = new PrintWriter(Files.newBufferedWriter(model))) {
            writer.println("package " + packageName + ";");
            writer.println();
            writer.println("""
                import java.util.List;

                public record DefinedFuzzTarget(
                    String targetClass,
                    List<String> dictionary,
                    List<String> dictionaryResources,
                    boolean enableImplicitly
                ) {
                    public static final String DIRECTORY = "io.micronaut.fuzzing.fuzz-targets";
                }
                """);
        }
    }
}

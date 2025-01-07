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
import org.intellij.lang.annotations.Language;

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
            @Language("java")
            String s = """
import java.io.OutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import io.micronaut.core.annotation.Internal;

@Internal
public record DefinedFuzzTarget(
    String targetClass,
    List<String> dictionary,
    List<String> dictionaryResources,
    boolean enableImplicitly
) {
    public static final String DIRECTORY = "io.micronaut.fuzzing.fuzz-targets";

    public void writeStaticDictionary(OutputStream out) throws IOException {
        if (dictionary() != null) {
            out.write("# Manually defined dictionary entries\\n".getBytes(StandardCharsets.UTF_8));
            for (String s : dictionary()) {
                out.write('"');
                for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
                    if (b == '"' || b == '\\\\') {
                        // escape \\ and "
                        out.write('\\\\');
                        out.write(b);
                    } else if (b >= ' ' && b <= '~') {
                        // printable ascii char
                        out.write((char) b);
                    } else {
                        out.write('\\\\');
                        out.write('x');
                        if ((b & 0xff) < 0x10) {
                            out.write('0');
                        }
                        out.write(Integer.toHexString(b & 0xff).getBytes(StandardCharsets.UTF_8));
                    }
                }
                out.write('"');
                out.write('\\n');
            }
        }
    }

    public static void writeResourceDictionaryPrefix(OutputStream out, String resourceName) throws IOException {
        out.write(("# Dictionary from " + resourceName + "\\n").getBytes(StandardCharsets.UTF_8));
    }
}
""";
            writer.println(s.stripIndent());
        }
    }
}

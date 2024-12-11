package io.micronaut.fuzzing.jazzer;

import org.gradle.api.DefaultTask;
import org.gradle.api.file.ConfigurableFileCollection;
import org.gradle.api.provider.ListProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Classpath;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFiles;
import org.gradle.api.tasks.Optional;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.stream.Collectors;

public abstract class BaseJazzerTask extends DefaultTask {
    @InputFiles
    @Nonnull
    @Classpath
    public abstract ConfigurableFileCollection getClasspath();

    @Input
    public abstract ListProperty<String> getTargetClasses();

    @Input
    @Optional
    public abstract ListProperty<String> getJvmArgs();

    @Input
    @Optional
    public abstract ListProperty<String> getInstrumentationIncludes();

    @Input
    @Optional
    public abstract ListProperty<String> getInstrumentationExcludes();

    @Input
    @Optional
    public abstract Property<Boolean> getOnlyAscii();

    void collectArgs(List<String> args, String targetClass) {
        args.add("--target_class=" + targetClass);
        if (getInstrumentationIncludes().isPresent() && !getInstrumentationIncludes().get().isEmpty()) {
            args.add("--instrumentation_includes=" + joinPlatform(getInstrumentationIncludes().get()));
        }
        if (getInstrumentationExcludes().isPresent() && !getInstrumentationExcludes().get().isEmpty()) {
            args.add("--instrumentation_excludes=" + joinPlatform(getInstrumentationExcludes().get()));
        }
        if (getOnlyAscii().isPresent()) {
            args.add("-only_ascii=" + (getOnlyAscii().get() ? "1" : "0"));
        }
    }

    static String joinPlatform(List<String> list) {
        // todo: ':' won't work on windows
        return list.stream().map(s -> s.replace(":", "\\:")).collect(Collectors.joining(":"));
    }
}

package io.micronaut.internal.jazzer;

import org.gradle.api.DefaultTask;
import org.gradle.api.file.ConfigurableFileCollection;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.ListProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Classpath;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputDirectory;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.InputFiles;
import org.gradle.api.tasks.Nested;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.TaskAction;
import org.gradle.jvm.toolchain.JavaInstallationMetadata;
import org.gradle.process.ExecOperations;

import javax.annotation.Nonnull;
import javax.inject.Inject;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public abstract class JazzerTask extends DefaultTask {
    @InputFiles
    @Nonnull
    @Classpath
    public abstract ConfigurableFileCollection getClasspath();

    @InputFile
    @Nonnull
    public abstract RegularFileProperty getJazzerBinary();

    @Input
    public abstract ListProperty<String> getTargetClasses();

    @Input
    @Optional
    public abstract ListProperty<String> getJvmArgs();

    @InputDirectory
    @Optional
    public abstract DirectoryProperty getCorpus();

    @Input
    @Optional
    public abstract ListProperty<String> getInstrumentationIncludes();

    @Input
    @Optional
    public abstract ListProperty<String> getInstrumentationExcludes();

    @Nested
    public abstract Property<JavaInstallationMetadata> getJavaInstallation();

    @Input
    @Optional
    public abstract Property<Integer> getForks();

    @Input
    @Optional
    public abstract Property<Integer> getJobs();

    @Input
    @Optional
    public abstract Property<Boolean> getOnlyAscii();

    @InputFile
    @Nonnull
    @Optional
    public abstract RegularFileProperty getMinimizeCrashFile();

    @InputFile
    @Nonnull
    @Optional
    public abstract RegularFileProperty getDictionaryFile();

    @OutputFile
    @Nonnull
    @Optional
    public abstract RegularFileProperty getCoverageDumpFile();

    @Input
    @Optional
    public abstract Property<Integer> getRssLimitMb();

    @Input
    @Optional
    public abstract Property<Duration> getMaxTotalTime();

    @Inject
    protected abstract ExecOperations getExecOperations();

    @TaskAction
    public void run() {
        for (String targetClass : getTargetClasses().get()) {
            getExecOperations().exec(spec -> {
                spec.setExecutable(getJazzerBinary().get().getAsFile().toString());
                List<String> args = new ArrayList<>();
                if (getForks().isPresent()) {
                    args.add("-fork=" + getForks().get());
                }
                if (getJobs().isPresent()) {
                    args.add("-jobs=" + getJobs().get());
                }
                args.add("--cp=" + getClasspath().getAsPath());
                args.add("--target_class=" + targetClass);
                args.add("--coverage_report=cov-report.txt");
                if (getCoverageDumpFile().isPresent()) {
                    args.add("--coverage_dump=" + getCoverageDumpFile().getAsFile().get().getPath());
                }
                if (getRssLimitMb().isPresent()) {
                    args.add("-rss_limit_mb=" + getRssLimitMb().get());
                }
                if (getMaxTotalTime().isPresent()) {
                    args.add("-max_total_time=" + getMaxTotalTime().get().toSeconds());
                }
                if (getJvmArgs().isPresent() && !getJvmArgs().get().isEmpty()) {
                    args.add("--jvm_args=" + joinPlatform(getJvmArgs().get()));
                }
                if (getInstrumentationIncludes().isPresent() && !getInstrumentationIncludes().get().isEmpty()) {
                    args.add("--instrumentation_includes=" + joinPlatform(getInstrumentationIncludes().get()));
                }
                if (getInstrumentationExcludes().isPresent() && !getInstrumentationExcludes().get().isEmpty()) {
                    args.add("--instrumentation_excludes=" + joinPlatform(getInstrumentationExcludes().get()));
                }
                if (getOnlyAscii().isPresent()) {
                    args.add("-only_ascii=" + (getOnlyAscii().get() ? "1" : "0"));
                }
                if (getDictionaryFile().isPresent()) {
                    args.add("-dict=" + getDictionaryFile().getAsFile().get().getPath());
                }
                if (getMinimizeCrashFile().isPresent()) {
                    args.add("-minimize_crash=1");
                    args.add(getMinimizeCrashFile().getAsFile().get().getPath());
                }
                if (getCorpus().isPresent() && !getMinimizeCrashFile().isPresent()) {
                    args.add(getCorpus().getAsFile().get().getPath());
                }
                spec.setArgs(args);
                getLogger().quiet("Jazzer command line: {}", String.join(" ", args));
                spec.environment("JAVA_HOME", getJavaInstallation().get().getInstallationPath());
            });
        }
    }

    private static String joinPlatform(List<String> list) {
        // todo: ':' won't work on windows
        return list.stream().map(s -> s.replace(":", "\\:")).collect(Collectors.joining(":"));
    }
}

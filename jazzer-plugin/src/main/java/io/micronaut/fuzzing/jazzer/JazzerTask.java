package io.micronaut.fuzzing.jazzer;

import io.micronaut.fuzzing.model.DefinedFuzzTarget;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputDirectory;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.Nested;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.TaskAction;
import org.gradle.jvm.toolchain.JavaInstallationMetadata;
import org.gradle.process.ExecOperations;

import javax.annotation.Nonnull;
import javax.inject.Inject;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public abstract class JazzerTask extends BaseJazzerTask {
    @InputFile
    @Nonnull
    public abstract RegularFileProperty getJazzerBinary();

    @InputDirectory
    @Optional
    public abstract DirectoryProperty getCorpus();

    @Nested
    public abstract Property<JavaInstallationMetadata> getJavaInstallation();

    @Input
    @Optional
    public abstract Property<Integer> getForks();

    @Input
    @Optional
    public abstract Property<Integer> getJobs();

    @InputFile
    @Nonnull
    @Optional
    public abstract RegularFileProperty getMinimizeCrashFile();

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
    public void run() throws IOException {
        try (ClasspathAccess classpathAccess = new ClasspathAccess()) {
            for (DefinedFuzzTarget target : findFuzzTargets(classpathAccess)) {
                Path tmpDictFile = null;
                try {
                    if (target.dictionary() != null) {
                        tmpDictFile = Files.createTempFile("jazzer-dict", ".dict");
                        try (OutputStream os = Files.newOutputStream(tmpDictFile)) {
                            buildDictionary(classpathAccess, os, target);
                        }
                    }
                    Path finalTmpDictFile = tmpDictFile;
                    getExecOperations().exec(spec -> {
                        spec.setExecutable(getJazzerBinary().get().getAsFile().toString());
                        List<String> args = new ArrayList<>();
                        collectArgs(args, target);
                        if (getForks().isPresent()) {
                            args.add("-fork=" + getForks().get());
                        }
                        if (getJobs().isPresent()) {
                            args.add("-jobs=" + getJobs().get());
                        }
                        args.add("--cp=" + getClasspath().getAsPath());

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
                        if (finalTmpDictFile != null) {
                            args.add("-dict=" + finalTmpDictFile);
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
                } finally {
                    if (tmpDictFile != null) {
                        Files.deleteIfExists(tmpDictFile);
                    }
                }
            }
        }
    }
}

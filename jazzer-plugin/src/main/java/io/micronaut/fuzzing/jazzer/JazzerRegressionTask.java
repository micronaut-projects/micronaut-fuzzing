package io.micronaut.fuzzing.jazzer;

import io.micronaut.fuzzing.model.DefinedFuzzTarget;
import org.gradle.api.file.ConfigurableFileCollection;
import org.gradle.api.provider.MapProperty;
import org.gradle.api.tasks.InputFiles;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.PathSensitive;
import org.gradle.api.tasks.PathSensitivity;
import org.gradle.api.tasks.TaskAction;
import org.gradle.process.ExecOperations;
import org.gradle.work.DisableCachingByDefault;

import javax.annotation.Nonnull;
import javax.inject.Inject;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@DisableCachingByDefault(because = "Runs Jazzer against fixed regression inputs")
public abstract class JazzerRegressionTask extends BaseJazzerTask {
    @InputFiles
    @PathSensitive(PathSensitivity.RELATIVE)
    @Nonnull
    public abstract ConfigurableFileCollection getRegressionInputs();

    @Input
    public abstract MapProperty<String, String> getBase64RegressionInputs();

    @Inject
    protected abstract ExecOperations getExecOperations();

    @TaskAction
    public void run() throws IOException {
        Map<String, String> base64Inputs = getBase64RegressionInputs().getOrElse(Map.of());
        if (getRegressionInputs().isEmpty() && base64Inputs.isEmpty()) {
            throw new IllegalStateException("No regression inputs configured");
        }
        List<Path> decodedInputs = new ArrayList<>();
        try (ClasspathAccess classpathAccess = new ClasspathAccess()) {
            for (Map.Entry<String, String> entry : base64Inputs.entrySet()) {
                Path input = Files.createTempFile("jazzer-regression-" + entry.getKey() + "-", ".input");
                decodedInputs.add(input);
                Files.write(input, Base64.getMimeDecoder().decode(entry.getValue()));
            }
            for (DefinedFuzzTarget target : findFuzzTargets(classpathAccess)) {
                for (File input : getRegressionInputs().getFiles()) {
                    runJazzer(target, input.toPath());
                }
                for (Path input : decodedInputs) {
                    runJazzer(target, input);
                }
            }
        } finally {
            for (Path input : decodedInputs) {
                Files.deleteIfExists(input);
            }
        }
    }

    private void runJazzer(DefinedFuzzTarget target, Path input) {
        getExecOperations().javaexec(spec -> {
            List<String> args = new ArrayList<>();
            collectArgs(args, target);
            spec.classpath(getClasspath());
            args.add("--cp=" + getClasspath().getAsPath());
            args.add(input.toString());
            spec.jvmArgs(getJvmArgs().getOrElse(List.of()));
            spec.setArgs(args);
            spec.getMainClass().set("com.code_intelligence.jazzer.Jazzer");
            getLogger().quiet("Jazzer regression command line: {}", String.join(" ", spec.getCommandLine()));
        });
    }
}

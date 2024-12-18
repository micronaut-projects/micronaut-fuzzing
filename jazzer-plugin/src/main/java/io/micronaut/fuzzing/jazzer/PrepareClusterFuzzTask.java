package io.micronaut.fuzzing.jazzer;

import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.OutputDirectory;
import org.gradle.api.tasks.TaskAction;

import java.io.File;
import java.io.IOException;
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public abstract class PrepareClusterFuzzTask extends BaseJazzerTask {
    @OutputDirectory
    public abstract DirectoryProperty getOutputDirectory();

    @InputFile
    public abstract RegularFileProperty getAgent();

    @TaskAction
    public void run() throws IOException {
        Path libs = getOutputDirectory().dir("libs").get().getAsFile().toPath();
        try {
            Files.createDirectories(libs);
        } catch (IOException ignored) {
        }
        CopyOption[] copyOptions = new CopyOption[]{StandardCopyOption.REPLACE_EXISTING};
        for (File library : getClasspath().getFiles()) {
            Files.copy(library.toPath(), libs.resolve(library.getName()), copyOptions);
        }
        Files.copy(getAgent().get().getAsFile().toPath(), libs.resolve("jazzer_agent_deploy.jar"), copyOptions);
        for (String targetClass : getTargetClasses().get()) {
            List<String> args = new ArrayList<>();
            collectArgs(args, targetClass);
            String sh = """
                #!/bin/bash
                # LLVMFuzzerTestOneInput <-- for fuzzer detection (see test_all.py)
                this_dir=$(dirname "$0")
                exec $this_dir/jazzer_driver --agent_path=$this_dir/jazzer_agent_deploy.jar --cp=$this_dir'/libs/*' %s $@
                """.formatted(String.join(" ", args));
            Path targetPath = getOutputDirectory().file(targetClass).get().getAsFile().toPath();
            Files.writeString(targetPath, sh);
            Files.setPosixFilePermissions(targetPath, Set.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE,

                PosixFilePermission.GROUP_READ,
                PosixFilePermission.GROUP_EXECUTE,

                PosixFilePermission.OTHERS_READ,
                PosixFilePermission.OTHERS_EXECUTE
            ));
        }
    }
}

package io.micronaut.fuzzing.jazzer;

import org.gradle.api.file.DirectoryProperty;
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

    @TaskAction
    public void run() throws IOException {
        Path libs = getOutputDirectory().dir("libs").get().getAsFile().toPath();
        try {
            Files.createDirectories(libs);
        } catch (IOException ignored) {
        }
        CopyOption[] copyOptions = new CopyOption[]{StandardCopyOption.REPLACE_EXISTING};
        List<String> cp = new ArrayList<>();
        for (File library : getClasspath().getFiles()) {
            Files.copy(library.toPath(), libs.resolve(library.getName()), copyOptions);
            cp.add("$this_dir/libs/" + library.getName());
        }
        for (String targetClass : getTargetClasses().get()) {
            List<String> args = new ArrayList<>();
            collectArgs(args, targetClass);
            args.add("--cp=" + String.join(":", cp) + "::$this_dir");
            String sh = """
                #!/bin/bash
                # LLVMFuzzerTestOneInput <-- for fuzzer detection (see test_all.py)
                this_dir=$(dirname "$0")
                LD_LIBRARY_PATH="$JVM_LD_LIBRARY_PATH":$this_dir $this_dir/jazzer_driver --agent_path=$this_dir/jazzer_agent_deploy.jar %s $@
                """.formatted(String.join(" ", args));
            Path targetPath = getOutputDirectory().file(targetClass.substring(targetClass.lastIndexOf('.') + 1)).get().getAsFile().toPath();
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

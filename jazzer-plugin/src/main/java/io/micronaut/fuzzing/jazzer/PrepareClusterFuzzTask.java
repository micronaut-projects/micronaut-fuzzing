package io.micronaut.fuzzing.jazzer;

import io.micronaut.fuzzing.processor.DefinedFuzzTarget;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.tasks.OutputDirectory;
import org.gradle.api.tasks.TaskAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.CopyOption;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

public abstract class PrepareClusterFuzzTask extends BaseJazzerTask {
    private static final Logger LOG = LoggerFactory.getLogger(PrepareClusterFuzzTask.class);

    @OutputDirectory
    public abstract DirectoryProperty getOutputDirectory();

    @TaskAction
    public void run() throws IOException {
        // has to be the top-level /out directory for the fuzz introspector to find the jars
        Path libs = getOutputDirectory().get().getAsFile().toPath();

        CopyOption[] copyOptions = new CopyOption[]{StandardCopyOption.REPLACE_EXISTING};
        List<String> cp = new ArrayList<>();
        List<File> copiedFiles = new ArrayList<>();
        for (File library : getClasspath().getFiles()) {
            Path dst = libs.resolve(library.getName());
            copiedFiles.add(dst.toFile());
            Files.copy(library.toPath(), dst, copyOptions);
            cp.add("$this_dir/" + library.getName());
        }
        try (ClasspathAccess classpathAccess = new ClasspathAccess(copiedFiles)) {
            // hack: remove class files with versions > java 17 so that the introspector doesn't hiccup
            for (Path versionsDir : classpathAccess.resolve("META-INF/versions")) {
                try (Stream<Path> versions = Files.list(versionsDir)) {
                    versions
                        .filter(p -> {
                            try {
                                return Integer.parseInt(p.getFileName().toString()) > 17;
                            } catch (NumberFormatException e) {
                                return false;
                            }
                        })
                        .forEach(dir -> {
                            LOG.info("For oss-fuzz introspector compatibility, deleting class files from: {}", dir);
                            try {
                                Files.walkFileTree(dir, new SimpleFileVisitor<>() {
                                    @Override
                                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                                        Files.delete(file);
                                        return FileVisitResult.CONTINUE;
                                    }
                                });
                            } catch (IOException e) {
                                throw new UncheckedIOException(e);
                            }
                        });
                }
            }

            List<DefinedFuzzTarget> targets = findFuzzTargets(classpathAccess);
            Map<String, String> targetNames = assignTargetNames(targets.stream().map(DefinedFuzzTarget::targetClass).toList());
            for (DefinedFuzzTarget target : targets) {
                List<String> args = new ArrayList<>();
                collectArgs(args, target);
                args.add("--cp=" + String.join(":", cp));
                String fileName = targetNames.get(target.targetClass());
                if (target.dictionary() != null || target.dictionaryResources() != null) {
                    File dictFile = getOutputDirectory().file("dict/" + fileName).get().getAsFile();
                    //noinspection ResultOfMethodCallIgnored
                    dictFile.getParentFile().mkdirs();
                    try (OutputStream os = new FileOutputStream(dictFile)) {
                        buildDictionary(classpathAccess, os, target);
                    }
                    args.add("-dict=$this_dir/" + fileName);
                }
                String sh = """
                #!/bin/bash
                # LLVMFuzzerTestOneInput <-- for fuzzer detection (see test_all.py)
                this_dir=$(dirname "$0")
                LD_LIBRARY_PATH="$JVM_LD_LIBRARY_PATH":$this_dir $this_dir/jazzer_driver --agent_path=$this_dir/jazzer_agent_deploy.jar %s $@
                """.formatted(String.join(" ", args));
                Path targetPath = getOutputDirectory().file(fileName).get().getAsFile().toPath();
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

    static Map<String, String> assignTargetNames(Collection<String> targetClasses) {
        Map<String, List<String>> bySimpleName = new HashMap<>();
        for (String targetClass : targetClasses) {
            bySimpleName.computeIfAbsent(targetClass.substring(targetClass.lastIndexOf('.') + 1), k -> new ArrayList<>())
                .add(targetClass);
        }
        Map<String, String> targetNames = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : bySimpleName.entrySet()) {
            if (entry.getValue().size() > 1) {
                // multiple targets with the same simple name. remove any common prefix
                String first = entry.getValue().get(0);
                int splitIndex = first.lastIndexOf('.') + 1;
                while (true) {
                    String common = first.substring(0, splitIndex);
                    if (entry.getValue().stream().allMatch(s -> s.startsWith(common))) {
                        break;
                    } else {
                        splitIndex = first.lastIndexOf('.', splitIndex - 2) + 1;
                    }
                }
                for (String targetClass : entry.getValue()) {
                    targetNames.put(targetClass, targetClass.substring(splitIndex).replace('.', '_'));
                }
            } else {
                targetNames.put(entry.getValue().get(0), entry.getKey());
            }
        }
        return targetNames;
    }
}

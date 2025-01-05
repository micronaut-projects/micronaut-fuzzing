package io.micronaut.fuzzing.jazzer;

import io.micronaut.fuzzing.processor.DefinedFuzzTarget;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.provider.SetProperty;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.OutputDirectory;
import org.gradle.api.tasks.TaskAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.CopyOption;
import java.nio.file.FileAlreadyExistsException;
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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public abstract class PrepareClusterFuzzTask extends BaseJazzerTask {
    private static final Logger LOG = LoggerFactory.getLogger(PrepareClusterFuzzTask.class);

    @OutputDirectory
    public abstract DirectoryProperty getOutputDirectory();

    /**
     * Class name patterns to include in the introspector report. By default, all dependencies are
     * included, but this can be too much for the report.
     */
    @Input
    @Optional
    public abstract SetProperty<String> getIntrospectorIncludes();

    @TaskAction
    public void run() throws IOException {
        Path libs = getOutputDirectory().dir("libs").get().getAsFile().toPath();
        try {
            Files.createDirectories(libs);
        } catch (FileAlreadyExistsException ignored) {
        }

        CopyOption[] copyOptions = new CopyOption[]{StandardCopyOption.REPLACE_EXISTING};
        List<String> cp = new ArrayList<>();
        for (File library : getClasspath().getFiles()) {
            Files.copy(library.toPath(), libs.resolve(library.getName()), copyOptions);
            cp.add("$this_dir/libs/" + library.getName());
        }

        try (ClasspathAccess classpathAccess = new ClasspathAccess()) {
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
                    args.add("-dict=$this_dir/dict/" + fileName);
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

    @TaskAction
    public void prepareIntrospectorJars() throws IOException {
        // prepare a separate set of jars in the top-level /out directory, just for the
        // introspector to find.

        List<File> forIntrospector = new ArrayList<>();
        for (File library : getClasspath().getFiles()) {
            File dst = getOutputDirectory().file(library.getName()).get().getAsFile();
            Files.copy(library.toPath(), dst.toPath(), StandardCopyOption.REPLACE_EXISTING);
            forIntrospector.add(dst);
        }
        try (ClasspathAccess classpathAccess = new ClasspathAccess(forIntrospector)) {
            Set<String> patterns = getIntrospectorIncludes().getOrNull();
            Set<String> introspectorIncludesExactMatch;
            List<String> introspectorIncludesPrefixes;
            if (patterns == null || patterns.isEmpty()) {
                introspectorIncludesExactMatch = null;
                introspectorIncludesPrefixes = null;
            } else {
                introspectorIncludesExactMatch = new HashSet<>();
                introspectorIncludesPrefixes = new ArrayList<>();
                for (String pattern : patterns) {
                    if (pattern.endsWith(".*")) {
                        introspectorIncludesPrefixes.add(pattern.substring(0, pattern.length() - 1));
                    } else {
                        introspectorIncludesExactMatch.add(pattern);
                    }
                }
            }
            classpathAccess.walkFileTree(root -> new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    visit(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    if (exc == null) {
                        visit(dir);
                    }
                    return FileVisitResult.CONTINUE;
                }

                private void visit(Path file) throws IOException {
                    Path relative = root.relativize(file);
                    boolean delete = false;
                    if (relative.startsWith("META-INF/versions") && relative.getNameCount() >= 3) {
                        try {
                            int version = Integer.parseInt(relative.getName(2).toString());
                            if (version > 17) {
                                // hack: remove class files with versions > java 17 so that the introspector doesn't hiccup
                                LOG.info("For oss-fuzz introspector compatibility, deleting class file: {}", relative);
                                delete = true;
                            }
                        } catch (NumberFormatException ignored) {
                        }
                        if (relative.getNameCount() > 3) {
                            relative = relative.subpath(3, relative.getNameCount());
                        }
                    }
                    String p = relative.toString();
                    if (introspectorIncludesPrefixes != null && p.endsWith(".class")) {
                        String className = p.substring(0, p.length() - 6).replace('/', '.');
                        if (!introspectorIncludesExactMatch.contains(className) &&
                            introspectorIncludesPrefixes.stream().noneMatch(className::startsWith)) {
                            delete = true;
                        }
                    }
                    if (delete) {
                        Files.delete(file);
                    }
                }
            });
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

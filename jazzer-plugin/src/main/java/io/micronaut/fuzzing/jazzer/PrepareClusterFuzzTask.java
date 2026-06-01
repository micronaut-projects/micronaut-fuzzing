package io.micronaut.fuzzing.jazzer;

import io.micronaut.fuzzing.model.DefinedFuzzTarget;
import org.gradle.api.Action;
import org.gradle.api.file.ConfigurableFileCollection;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.provider.SetProperty;
import org.gradle.api.tasks.Classpath;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFiles;
import org.gradle.api.tasks.Nested;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.OutputDirectory;
import org.gradle.api.tasks.TaskAction;
import org.gradle.process.ExecOperations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.gradle.work.DisableCachingByDefault;

import javax.annotation.Nonnull;
import javax.inject.Inject;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
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
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.Set;
import java.util.stream.Collectors;

@DisableCachingByDefault(because = "Prepares OSS-Fuzz output directories and executable wrapper scripts")
public abstract class PrepareClusterFuzzTask extends BaseJazzerTask {
    private static final Logger LOG = LoggerFactory.getLogger(PrepareClusterFuzzTask.class);

    @InputFiles
    @Nonnull
    @Classpath
    public abstract ConfigurableFileCollection getSourcePath();

    @OutputDirectory
    public abstract DirectoryProperty getOutputDirectory();

    /**
     * Introspector-specific settings. Note that these don't affect the actual fuzzing, only the
     * introspector report.
     */
    @Nested
    public abstract Introspector getIntrospector();

    /**
     * Settings for <a href="https://github.com/CodeIntelligenceTesting/jazzer/blob/main/docs/advanced.md#native-libraries">testing JNI code with jazzer</a>.
     */
    @Nested
    public abstract Jni getJni();

    @Inject
    protected abstract ExecOperations getExecOperations();

    @Input
    @Optional
    public abstract Property<String> getJavaHome();

    @Input
    @Optional
    public abstract Property<String> getSetupScript();

    /**
     * Maximum class file major version to write to OSS-Fuzz coverage sources. This does not affect
     * the classpath used to execute fuzz targets.
     */
    @Input
    @Optional
    public abstract Property<Integer> getCoverageClassFileMajorVersion();

    /**
     * Introspector-specific settings. Note that these don't affect the actual fuzzing, only the
     * introspector report.
     */
    public final void introspector(Action<? super Introspector> action) {
        action.execute(getIntrospector());
    }

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

        boolean jni = getJni().getEnabled().getOrElse(false);
        if (jni) {
            Path nativeSanitizersDir = getOutputDirectory().dir("native-sanitizers").get().getAsFile().toPath();
            try {
                Files.createDirectories(nativeSanitizersDir);
            } catch (FileAlreadyExistsException ignored) {
            }

            String lib = switch (getJni().getSanitizer().getOrElse("")) {
                case "address" -> "libclang_rt.asan.so";
                case "undefined" -> "libclang_rt.ubsan_standalone.so";
                default -> null;
            };
            if (lib != null) {
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                getExecOperations().exec(exec -> {
                    exec.commandLine("clang", "--print-file-name", lib);
                    exec.setStandardOutput(os);
                }).assertNormalExitValue();
                Path path = Path.of(os.toString(StandardCharsets.UTF_8).trim());
                if (Files.exists(path)) {
                    Files.copy(path, nativeSanitizersDir.resolve(lib), StandardCopyOption.REPLACE_EXISTING);
                } else {
                    LOG.warn("Sanitizer runtime not found: {}", path);
                }
            } else {
                LOG.warn("Unsupported sanitizer mode: {}", getJni().getSanitizer().getOrNull());
            }
        }

        try (ClasspathAccess classpathAccess = new ClasspathAccess()) {
            Integer coverageClassFileMajorVersion = validateCoverageClassFileMajorVersion();
            List<DefinedFuzzTarget> targets = findFuzzTargets(classpathAccess);
            Map<String, String> targetNames = assignTargetNames(targets.stream().map(DefinedFuzzTarget::targetClass).toList());
            for (DefinedFuzzTarget target : targets) {
                List<String> line = new ArrayList<>();
                line.add("LD_LIBRARY_PATH=" + (getJavaHome().isPresent() ? getJavaHome().get() + "/lib/server" : "\"$JVM_LD_LIBRARY_PATH\"") + ":$this_dir");
                if (getJavaHome().isPresent()) {
                    line.add("JAVA_HOME=" + getJavaHome().get());
                }
                if (jni) {
                    line.add("JAZZER_NATIVE_SANITIZERS_DIR=native-sanitizers");
                }
                line.add("$this_dir/jazzer_driver");
                if (jni) {
                    switch (getJni().getSanitizer().getOrElse("")) {
                        case "address" -> line.add("--asan");
                        case "undefined" -> line.add("--ubsan");
                        default -> {
                            // there was a warning above already
                        }
                    }
                }
                line.add("--agent_path=$this_dir/jazzer_agent_deploy.jar");
                collectArgs(line, target);
                line.add("--cp=" + String.join(":", cp));
                String fileName = targetNames.get(target.targetClass());
                if (target.dictionary() != null || target.dictionaryResources() != null) {
                    File dictFile = getOutputDirectory().file("dict/" + fileName).get().getAsFile();
                    //noinspection ResultOfMethodCallIgnored
                    dictFile.getParentFile().mkdirs();
                    try (OutputStream os = new FileOutputStream(dictFile)) {
                        buildDictionary(classpathAccess, os, target);
                    }
                    line.add("-dict=$this_dir/dict/" + fileName);
                }
                // These single quotes are very important. Without them, the JVM args will not
                // apply, but there will be no error. `-merge=1 --nohooks` will fail loudly, but
                // not when running inside oss-fuzz...
                line.add("'--jvm_args=" + getJvmArgs().get().stream().map(s -> s.replace(":", "\\:")).collect(Collectors.joining(":")) + "'");
                line.add("$@");
                String sh = """
                #!/bin/bash
                # LLVMFuzzerTestOneInput <-- for fuzzer detection (see test_all.py)
                this_dir=$(dirname "$0")
                export EXTERNAL_JAZZER_ARGS="$@"
                """ + getSetupScript().getOrElse("") + "\n" + String.join(" ", line);
                if (coverageClassFileMajorVersion != null) {
                    sh += "\n" + coverageClassFileMajorVersionScript(coverageClassFileMajorVersion);
                }
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
            ClassNameMatcher introspectorIncludes = compileIntrospectorIncludes();
            ClassNameMatcher introspectorExcludes = compileIntrospectorExcludes();
            classpathAccess.walkFileTree(root -> new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    if (!includeInIntrospector(introspectorIncludes, introspectorExcludes, root.relativize(file), true)) {
                        Files.delete(file);
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        }
    }

    private ClassNameMatcher compileIntrospectorExcludes() {
        return new ClassNameMatcher(getIntrospector().getExcludes().orElse(Set.of()).get());
    }

    private ClassNameMatcher compileIntrospectorIncludes() {
        Set<String> includePatterns = getIntrospector().getIncludes().getOrNull();
        ClassNameMatcher introspectorIncludes;
        if (includePatterns == null || includePatterns.isEmpty()) {
            introspectorIncludes = null;
        } else {
            introspectorIncludes = new ClassNameMatcher(includePatterns);
        }
        return introspectorIncludes;
    }

    private static OptionalInt parseMultiReleaseVersion(Path relativeClassPath) {
        if (relativeClassPath.startsWith("META-INF/versions") && relativeClassPath.getNameCount() >= 3) {
            try {
                return OptionalInt.of(Integer.parseInt(relativeClassPath.getName(2).toString()));
            } catch (NumberFormatException ignored) {
            }
        }
        return OptionalInt.empty();
    }

    private static Path stripMultiReleasePrefix(Path relativeClassPath) {
        if (relativeClassPath.startsWith("META-INF/versions") && relativeClassPath.getNameCount() > 3) {
            return relativeClassPath.subpath(3, relativeClassPath.getNameCount());
        } else {
            return relativeClassPath;
        }
    }

    private static boolean includeInIntrospector(ClassNameMatcher includes, ClassNameMatcher excludes, Path relative, boolean keepNonClasses) {
        if (parseMultiReleaseVersion(relative).orElse(-1) > 17) {
            // hack: remove class files with versions > java 17 so that the introspector doesn't hiccup
            LOG.info("For oss-fuzz introspector compatibility, deleting class file: {}", relative);
            return false;
        }
        relative = stripMultiReleasePrefix(relative);

        String p = relative.toString();
        if (!p.endsWith(".class")) {
            return keepNonClasses;
        }
        if ((includes != null || !excludes.isEmpty())) {
            String className = p.substring(0, p.length() - 6).replace('/', '.');
            if (includes != null && !includes.matches(className)) {
                return false;
            }
            //noinspection RedundantIfStatement
            if (excludes.matches(className)) {
                return false;
            }
        }
        return true;
    }

    @TaskAction
    public void prepareCoverageSources() throws Exception {
        try (ClasspathAccess classRoots = new ClasspathAccess(getClasspath());
             ClasspathAccess sourceRoots = new ClasspathAccess(getSourcePath())) {
            Path dest = getOutputDirectory().get().getAsFile().toPath().resolve("src");
            try {
                Files.createDirectories(dest);
            } catch (FileAlreadyExistsException ignored) {
            }

            ClassNameMatcher introspectorIncludes = compileIntrospectorIncludes();
            ClassNameMatcher introspectorExcludes = compileIntrospectorExcludes();
            Integer coverageClassFileMajorVersion = validateCoverageClassFileMajorVersion();
            classRoots.walkFileTree(classRoot -> new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Path classRelative = classRoot.relativize(file);
                    if (includeInIntrospector(introspectorIncludes, introspectorExcludes, classRelative, false)) {
                        classRelative = stripMultiReleasePrefix(classRelative);

                        Path classDest = dest.resolve(classRelative.toString());
                        try {
                            Files.createDirectories(classDest.getParent());
                        } catch (FileAlreadyExistsException ignored) {
                        }
                        if (coverageClassFileMajorVersion == null) {
                            Files.copy(file, classDest, StandardCopyOption.REPLACE_EXISTING);
                        } else {
                            Files.write(classDest, limitClassFileMajorVersion(Files.readAllBytes(file), coverageClassFileMajorVersion));
                        }

                        String sourceName = classRelative.toString();
                        sourceName = sourceName.substring(0, sourceName.length() - ".class".length()) + ".java";
                        List<Path> sourcePaths = sourceRoots.resolve(sourceName);
                        if (!sourcePaths.isEmpty()) {
                            Files.copy(sourcePaths.getFirst(), dest.resolve(sourceName), StandardCopyOption.REPLACE_EXISTING);
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }
            });

        }
    }

    static String coverageClassFileMajorVersionScript(int maxMajorVersion) {
        return """
            jazzer_status=$?
            dump_classes_dirs=()
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --dump_classes_dir=*|-dump_classes_dir=*)
                        dump_classes_dirs+=("${1#*=}")
                        ;;
                    --dump_classes_dir|-dump_classes_dir)
                        shift
                        if [[ $# -gt 0 ]]; then
                            dump_classes_dirs+=("$1")
                        fi
                        ;;
                esac
                shift
            done
            if [[ ${#dump_classes_dirs[@]} -gt 0 ]]; then
                python3 - "%d" "${dump_classes_dirs[@]}" <<'PY'
            import pathlib
            import sys

            max_major_version = int(sys.argv[1])
            for dump_classes_dir in sys.argv[2:]:
                root = pathlib.Path(dump_classes_dir)
                if not root.exists():
                    continue
                for class_file in root.rglob("*.class"):
                    data = bytearray(class_file.read_bytes())
                    if len(data) < 8 or data[:4] != bytes((0xca, 0xfe, 0xba, 0xbe)):
                        continue
                    major_version = (data[6] << 8) | data[7]
                    if major_version > max_major_version:
                        data[6] = (max_major_version >> 8) & 0xff
                        data[7] = max_major_version & 0xff
                        class_file.write_bytes(data)
            PY
            fi
            exit "$jazzer_status"
            """.formatted(maxMajorVersion);
    }

    private Integer validateCoverageClassFileMajorVersion() {
        Integer majorVersion = getCoverageClassFileMajorVersion().getOrNull();
        if (majorVersion != null && (majorVersion <= 0 || majorVersion > 0xffff)) {
            throw new IllegalArgumentException("coverageClassFileMajorVersion must be between 1 and 65535");
        }
        return majorVersion;
    }

    static byte[] limitClassFileMajorVersion(byte[] classFile, int maxMajorVersion) {
        if (classFile.length < 8 ||
            classFile[0] != (byte) 0xca ||
            classFile[1] != (byte) 0xfe ||
            classFile[2] != (byte) 0xba ||
            classFile[3] != (byte) 0xbe) {
            return classFile;
        }
        int majorVersion = ((classFile[6] & 0xff) << 8) | (classFile[7] & 0xff);
        if (majorVersion <= maxMajorVersion) {
            return classFile;
        }
        byte[] compatible = Arrays.copyOf(classFile, classFile.length);
        compatible[6] = (byte) (maxMajorVersion >>> 8);
        compatible[7] = (byte) maxMajorVersion;
        return compatible;
    }

    public interface Introspector {
        /**
         * Class name patterns to include in the introspector report. By default, all dependencies are
         * included, but this can be too much for the report.
         */
        @Input
        SetProperty<String> getIncludes();

        /**
         * Class name patterns to exclude in the introspector report. By default, all dependencies are
         * included, but this can be too much for the report.
         * <p>This takes precedence over {@link #getIncludes()}.
         */
        @Input
        SetProperty<String> getExcludes();
    }

    public interface Jni {
        /**
         * Whether to enable JNI fuzzing support. Disabled by default.
         * <p>Enabling this will copy the sanitizer runtime, set
         * {@code JAZZER_NATIVE_SANITIZERS_DIR}, and pass the appropriate flag for jazzer to
         * include the runtime.
         */
        @Input
        @Optional
        Property<Boolean> getEnabled();

        /**
         * The sanitizer to prepare for. The default is the {@code SANITIZER} environment variable
         * set by OSS-Fuzz.
         */
        @Input
        @Optional
        Property<String> getSanitizer();
    }
}

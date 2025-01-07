package io.micronaut.fuzzing.jazzer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micronaut.fuzzing.model.DefinedFuzzTarget;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.ConfigurableFileCollection;
import org.gradle.api.provider.ListProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.provider.SetProperty;
import org.gradle.api.tasks.Classpath;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFiles;
import org.gradle.api.tasks.Optional;

import javax.annotation.Nonnull;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public abstract class BaseJazzerTask extends DefaultTask {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @InputFiles
    @Nonnull
    @Classpath
    public abstract ConfigurableFileCollection getClasspath();

    @Input
    @Optional
    public abstract SetProperty<String> getTargets();

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

    protected final List<DefinedFuzzTarget> findFuzzTargets(ClasspathAccess cp) throws IOException {
        List<DefinedFuzzTarget> definedFuzzTargets = new ArrayList<>();
        for (Path dir : cp.resolve("META-INF/" + DefinedFuzzTarget.DIRECTORY)) {
            if (Files.isDirectory(dir)) {
                try (Stream<Path> stream = Files.list(dir)) {
                    List<Path> files = stream.toList();
                    for (Path file : files) {
                        try (InputStream inputStream = Files.newInputStream(file)) {
                            definedFuzzTargets.addAll(objectMapper.readValue(inputStream, new TypeReference<List<DefinedFuzzTarget>>() {
                            }));
                        }
                    }
                }
            }
        }
        if (definedFuzzTargets.isEmpty()) {
            throw new IllegalStateException("No fuzz targets defined");
        }
        if (getTargets().isPresent() && !getTargets().get().isEmpty()) {
            Set<String> enabled = getTargets().get();
            definedFuzzTargets.removeIf(t -> !enabled.contains(t.targetClass()));
            for (String e : enabled) {
                if (definedFuzzTargets.stream().noneMatch(t -> t.targetClass().equals(e))) {
                    throw new IllegalStateException("Target enabled but not found: " + e);
                }
            }
        } else {
            definedFuzzTargets.removeIf(t -> !t.enableImplicitly());
        }
        return definedFuzzTargets;
    }

    protected final void buildDictionary(ClasspathAccess cp, OutputStream out, DefinedFuzzTarget target) throws IOException {
        if (target.dictionary() != null) {
            out.write("# Manually defined dictionary entries\n".getBytes(StandardCharsets.UTF_8));
            for (String s : target.dictionary()) {
                out.write('"');
                for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
                    if (b == '"' || b == '\\') {
                        // escape \ and "
                        out.write('\\');
                        out.write(b);
                    } else if (b >= ' ' && b <= '~') {
                        // printable ascii char
                        out.write((char) b);
                    } else {
                        out.write('\\');
                        out.write('x');
                        if ((b & 0xff) < 0x10) {
                            out.write('0');
                        }
                        out.write(Integer.toHexString(b & 0xff).getBytes(StandardCharsets.UTF_8));
                    }
                }
                out.write('"');
                out.write('\n');
            }
        }
        if (target.dictionaryResources() != null) {
            for (String r : target.dictionaryResources()) {
                List<Path> resolved = cp.resolve(r);
                if (resolved.isEmpty()) {
                    throw new IllegalStateException("Failed to find declared dictionary resource " + r + " for target " + target.targetClass());
                }
                for (Path path : resolved) {
                    out.write(("# Dictionary from " + r + "\n").getBytes(StandardCharsets.UTF_8));
                    Files.copy(path, out);
                    out.write('\n');
                }
            }
        }
    }

    protected final void collectArgs(List<String> args, DefinedFuzzTarget target) {
        args.add("--target_class=" + target.targetClass());
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

    protected final class ClasspathAccess implements Closeable {
        private final List<FileSystem> zipFileSystems = new ArrayList<>();
        private final List<Path> roots = new ArrayList<>();

        public ClasspathAccess() throws IOException {
            this(getClasspath());
        }

        public ClasspathAccess(Iterable<File> files) throws IOException {
            for (File f : files) {
                Path p = f.toPath();
                if (Files.isDirectory(p)) {
                    roots.add(p);
                } else {
                    FileSystem zipfs = FileSystems.newFileSystem(p);
                    zipFileSystems.add(zipfs);
                    roots.add(zipfs.getRootDirectories().iterator().next());
                }
            }
        }

        public void walkFileTree(Function<Path, FileVisitor<Path>> visitor) throws IOException {
            for (Path root : roots) {
                Files.walkFileTree(root, visitor.apply(root));
            }
        }

        private List<Path> resolve(String p) {
            List<Path> result = new ArrayList<>();
            for (Path root : roots) {
                Path resolved = root.resolve(p).normalize();
                if (resolved.startsWith(root) && Files.exists(resolved)) {
                    result.add(resolved);
                }
            }
            return result;
        }

        @Override
        public void close() throws IOException {
            for (FileSystem zfs : zipFileSystems) {
                zfs.close();
            }
        }
    }
}

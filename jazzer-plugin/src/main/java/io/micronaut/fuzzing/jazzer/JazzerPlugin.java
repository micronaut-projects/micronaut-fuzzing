package io.micronaut.fuzzing.jazzer;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.artifacts.Configuration;
import org.gradle.api.artifacts.component.ModuleComponentIdentifier;
import org.gradle.api.artifacts.result.ResolvedArtifactResult;
import org.gradle.api.plugins.JavaPlugin;
import org.gradle.internal.component.external.model.ModuleComponentArtifactIdentifier;
import org.gradle.jvm.toolchain.JavaToolchainService;
import org.gradle.language.base.plugins.LifecycleBasePlugin;

import javax.inject.Inject;
import java.io.File;
import java.util.Map;

public abstract class JazzerPlugin implements Plugin<Project> {
    @Inject
    protected abstract JavaToolchainService getJavaToolchainService();

    @Override
    public void apply(Project project) {
        Configuration runtimeClasspath = project.getConfigurations().getByName(JavaPlugin.RUNTIME_CLASSPATH_CONFIGURATION_NAME);
        Configuration jazzerBaseClasspath = project.getConfigurations().create("jazzerClasspath", c -> {
            c.extendsFrom(runtimeClasspath);
            // exclude jazzer, jazzer-api etc, since they are supplied by the runtime.
            c.exclude(Map.of("group", "com.code-intelligence"));
            c.exclude(Map.of("group", "io.micronaut.fuzzing", "module", "micronaut-fuzzing-runner"));
        });
        jazzerBaseClasspath.getDependencies().add(project.getDependencies().create(project));

        project.getTasks().register("jazzer", JazzerTask.class, task -> {
            Configuration jazzerWithRuntimeClasspath = project.getConfigurations().create("jazzerWithRuntimeClasspath", c -> {
                c.extendsFrom(runtimeClasspath);
                c.exclude(Map.of("group", "io.micronaut.fuzzing", "module", "micronaut-fuzzing-runner"));
            });
            jazzerWithRuntimeClasspath.getDependencies().add(project.getDependencies().create(project));

            // add a dependency on jazzer standalone that matches the jazzer-api version
            String jazzerVersion = null;
            for (ResolvedArtifactResult artifact : runtimeClasspath.getIncoming().getArtifacts()) {
                if (artifact.getId() instanceof ModuleComponentArtifactIdentifier mcai) {
                    ModuleComponentIdentifier ci = mcai.getComponentIdentifier();
                    if ("com.code-intelligence".equals(ci.getGroup()) &&
                        ("jazzer-api".equals(ci.getModule()) || "jazzer".equals(ci.getModule()))) {
                        jazzerVersion = ci.getVersion();
                        break;
                    }
                }
            }
            if (jazzerVersion != null) {
                jazzerWithRuntimeClasspath.getDependencies().add(project.getDependencies().create("com.code-intelligence:jazzer:" + jazzerVersion));
            }

            task.setGroup(LifecycleBasePlugin.CHECK_TASK_NAME);
            task.setDescription("Runs jazzer for fuzzing.");

            task.getClasspath().setFrom(jazzerWithRuntimeClasspath);
        });
        project.getTasks().register("prepareClusterFuzz", PrepareClusterFuzzTask.class, task -> {
            task.setGroup(LifecycleBasePlugin.ASSEMBLE_TASK_NAME);
            task.setDescription("Prepare run scripts of the different fuzz targets for ClusterFuzz (OSS-Fuzz) execution");

            task.getClasspath().setFrom(jazzerBaseClasspath);
            String out = System.getenv("OUT");
            if (out != null) {
                task.getOutputDirectory().set(new File(out));
            }
        });
    }
}

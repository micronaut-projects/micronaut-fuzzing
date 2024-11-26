package io.micronaut.internal.jazzer;

import org.gradle.api.JavaVersion;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.artifacts.Configuration;
import org.gradle.api.plugins.JavaPlugin;
import org.gradle.jvm.toolchain.JavaLanguageVersion;
import org.gradle.jvm.toolchain.JavaLauncher;
import org.gradle.jvm.toolchain.JavaToolchainService;
import org.gradle.language.base.plugins.LifecycleBasePlugin;

import javax.inject.Inject;
import java.io.File;

public abstract class JazzerPlugin implements Plugin<Project> {
    @Inject
    protected abstract JavaToolchainService getJavaToolchainService();

    @Override
    public void apply(Project project) {
        Configuration jazzerClasspath = project.getConfigurations().create("jazzerClasspath", c ->
            c.extendsFrom(project.getConfigurations().getByName(JavaPlugin.RUNTIME_CLASSPATH_CONFIGURATION_NAME)));
        jazzerClasspath.getDependencies().add(project.getDependencies().create(project));

        project.getTasks().register("jazzer", JazzerTask.class, task -> {
            task.setGroup(LifecycleBasePlugin.CHECK_TASK_NAME);
            task.setDescription("Runs jazzer for fuzzing.");

            task.getClasspath().setFrom(jazzerClasspath);
            task.getJavaInstallation().set(
                    getJavaToolchainService()
                            .launcherFor(spec -> spec.getLanguageVersion().set(JavaLanguageVersion.of(JavaVersion.current().getMajorVersion())))
                            .map(JavaLauncher::getMetadata)
            );
        });
        project.getTasks().register("prepareClusterFuzz", PrepareClusterFuzzTask.class, task -> {
            task.setGroup(LifecycleBasePlugin.ASSEMBLE_TASK_NAME);
            task.setDescription("Prepare run scripts of the different fuzz targets for ClusterFuzz (OSS-Fuzz) execution");

            task.getClasspath().setFrom(jazzerClasspath);
            task.getAgent().set(new File("/usr/local/bin/jazzer_agent_deploy.jar"));
            String out = System.getenv("OUT");
            if (out != null) {
                //throw new IllegalStateException("No OUT environment variable found. This task should run on OSS-Fuzz only!");
                task.getOutputDirectory().set(new File(out));
            }
        });
    }
}

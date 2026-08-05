package io.micronaut.fuzzing.jazzer;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.artifacts.Configuration;
import org.gradle.api.artifacts.component.ModuleComponentIdentifier;
import org.gradle.api.artifacts.result.ResolvedArtifactResult;
import org.gradle.api.attributes.Bundling;
import org.gradle.api.attributes.Category;
import org.gradle.api.attributes.DocsType;
import org.gradle.api.attributes.Usage;
import org.gradle.api.plugins.JavaPlugin;
import org.gradle.internal.component.external.model.ModuleComponentArtifactIdentifier;
import org.gradle.language.base.plugins.LifecycleBasePlugin;

import java.io.File;
import java.util.Map;

public abstract class JazzerPlugin implements Plugin<Project> {
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

        Configuration jazzerWithRuntimeClasspath = project.getConfigurations().create("jazzerWithRuntimeClasspath", c -> {
            c.extendsFrom(runtimeClasspath);
            c.exclude(Map.of("group", "io.micronaut.fuzzing", "module", "micronaut-fuzzing-runner"));
        });
        jazzerWithRuntimeClasspath.getDependencies().add(project.getDependencies().create(project));

        project.afterEvaluate(p -> {
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
        });

        project.getTasks().withType(JazzerRegressionTask.class).configureEach(task -> {
            task.getClasspath().setFrom(jazzerWithRuntimeClasspath);
        });

        project.getTasks().register("jazzer", JazzerTask.class, task -> {

            task.setGroup(LifecycleBasePlugin.CHECK_TASK_NAME);
            task.setDescription("Runs jazzer for fuzzing.");

            task.getClasspath().setFrom(jazzerWithRuntimeClasspath);
        });
        project.getTasks().register("jazzerRegression", JazzerRegressionTask.class, task -> {
            task.setGroup(LifecycleBasePlugin.CHECK_TASK_NAME);
            task.setDescription("Runs Jazzer fuzz targets against configured regression inputs.");
        });
        project.getTasks().register("prepareClusterFuzz", PrepareClusterFuzzTask.class, task -> {
            task.setGroup(LifecycleBasePlugin.ASSEMBLE_TASK_NAME);
            task.setDescription("Prepare run scripts of the different fuzz targets for ClusterFuzz (OSS-Fuzz) execution");

            task.getClasspath().setFrom(jazzerBaseClasspath);
            task.getOutputDirectory().convention(project.getLayout().getBuildDirectory().dir("cluster-fuzz"));
            task.getJazzerDriver().convention("jazzer_driver");
            task.getJazzerAgent().convention("jazzer_agent_deploy.jar");
            task.getSourcePath().setFrom(jazzerBaseClasspath.getIncoming().artifactView(v -> {
                v.withVariantReselection();
                v.attributes(attributes -> {
                    attributes.attribute(Usage.USAGE_ATTRIBUTE, project.getObjects().named(Usage.class, Usage.JAVA_RUNTIME));
                    attributes.attribute(Category.CATEGORY_ATTRIBUTE, project.getObjects().named(Category.class, Category.DOCUMENTATION));
                    attributes.attribute(Bundling.BUNDLING_ATTRIBUTE, project.getObjects().named(Bundling.class, Bundling.EXTERNAL));
                    attributes.attribute(DocsType.DOCS_TYPE_ATTRIBUTE, project.getObjects().named(DocsType.class, DocsType.SOURCES));
                });
            }).getFiles());
            String out = System.getenv("OUT");
            if (out != null) {
                task.getOutputDirectory().set(new File(out));
            }
            String sanitizer = System.getenv("SANITIZER");
            if (sanitizer != null) {
                task.getJni().getSanitizer().set(sanitizer);
            }
        });
    }
}

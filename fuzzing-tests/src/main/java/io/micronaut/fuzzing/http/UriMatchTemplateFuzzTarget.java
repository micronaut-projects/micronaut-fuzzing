package io.micronaut.fuzzing.http;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.http.uri.UriMatchTemplate;

@FuzzTarget
@HttpDict
@Dict({
    "{", "}", "{?", "{+", "{#", "{/", "{.", "{&",
    "*", ":", ",", "/", "/users/", "/api/",
    "{id}", "{id*}", "{id:3}", "{?q,limit}",
    "%2F", "%00", "//", "/../",
})
public class UriMatchTemplateFuzzTarget {

    private static final UriMatchTemplate[] FIXED_TEMPLATES;

    static {
        FIXED_TEMPLATES = new UriMatchTemplate[]{
            new UriMatchTemplate(SimpleController.ECHO_PATH + "/{foo}"),
            new UriMatchTemplate("/echo-query{?foo}"),
            new UriMatchTemplate("/echo-request-bean/{id}{?filter}"),
            new UriMatchTemplate("/users/{userId}/orders/{orderId}"),
        };
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        int scenario = data.consumeInt(0, 3);

        switch (scenario) {
            case 0 -> {
                String template = data.consumeRemainingAsString();
                try {
                    new UriMatchTemplate(template);
                } catch (IllegalArgumentException | IllegalStateException ignored) {
                }
            }
            case 1 -> {
                UriMatchTemplate t = data.pickValue(FIXED_TEMPLATES);
                String path = data.consumeRemainingAsString();
                t.match(path);  // retourne Optional — pas d'exception attendue ici
            }
            case 2 -> {
                String template = data.consumeString(300);
                String path = data.consumeRemainingAsString();
                try {
                    UriMatchTemplate t = new UriMatchTemplate(template);
                    t.match(path).ifPresent(info -> info.getVariableValues());
                } catch (IllegalArgumentException | IllegalStateException ignored) {

                }
            }
            case 3 -> {
                int count = data.consumeInt(1, 5);
                String path = data.consumeString(200);
                for (int i = 0; i < count; i++) {
                    String template = data.consumeString(100);
                    try {
                        new UriMatchTemplate(template).match(path);
                    } catch (IllegalArgumentException | IllegalStateException ignored) {

                    }
                }
            }
        }
    }
}


package io.micronaut.fuzzing.http;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@MicronautTest
class SimpleControllerTest {
    @Inject
    @Client("/")
    HttpClient client;

    @Test
    void simple() {
        Assertions.assertEquals("index", client.toBlocking().retrieve("/"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        SimpleController.ECHO_PUBLISHER,
        SimpleController.ECHO_ARRAY,
        SimpleController.ECHO_STRING
    })
    void echo(String path) {
        Assertions.assertEquals("{}", client.toBlocking().retrieve(HttpRequest.POST(path, "{}")));
    }

    @Test
    void echoPiece() {
        Assertions.assertEquals("bar", client.toBlocking().retrieve(HttpRequest.POST(SimpleController.ECHO_PIECE_JSON, "{\"foo\": \"bar\"}")));
        Assertions.assertEquals("bar", client.toBlocking().retrieve(HttpRequest.POST(SimpleController.ECHO_PIECE_JSON, "foo=bar").contentType(MediaType.APPLICATION_FORM_URLENCODED)));
    }
}

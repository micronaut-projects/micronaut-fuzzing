package io.micronaut.fuzzing.http;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.multipart.MultipartBody;
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
    @Test
    void echoQuery() {
        Assertions.assertEquals("hello",
            client.toBlocking().retrieve(SimpleController.ECHO_QUERY + "?foo=hello"));
    }


    @Test
    void echoPath() {
        Assertions.assertEquals("world",
            client.toBlocking().retrieve(SimpleController.ECHO_PATH + "/world"));
    }

    @Test
    void echoHeader() {
        Assertions.assertEquals("myvalue",
            client.toBlocking().retrieve(
                HttpRequest.GET(SimpleController.ECHO_HEADER)
                    .header("X-Foo", "myvalue")));
    }

    @Test
    void echoForm() {
        Assertions.assertEquals("bar",
            client.toBlocking().retrieve(
                HttpRequest.POST(SimpleController.ECHO_FORM, "foo=bar")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)));
    }

    @Test
    void echoFormPair() {
        Assertions.assertEquals("alice:bob",
            client.toBlocking().retrieve(
                HttpRequest.POST(SimpleController.ECHO_FORM_PAIR, "foo=alice&bar=bob")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)));
    }

    @Test
    void echoCookieAbsent() {
        Assertions.assertEquals("null:null",
            client.toBlocking().retrieve(
                HttpRequest.GET(SimpleController.ECHO_COOKIE)));
    }

    @Test
    void echoCookiePresent() {
        Assertions.assertEquals("abc123:dark",
            client.toBlocking().retrieve(
                HttpRequest.GET(SimpleController.ECHO_COOKIE)
                    .cookie(io.micronaut.http.cookie.Cookie.of("session", "abc123"))
                    .cookie(io.micronaut.http.cookie.Cookie.of("theme", "dark"))));
    }

    @Test
    void echoBean() {
        Assertions.assertEquals("search:2:true",
            client.toBlocking().retrieve(
                SimpleController.ECHO_BEAN + "?keyword=search&page=2&active=true"));
    }

    @Test
    void echoBeanAllNull() {
        Assertions.assertEquals("null:null:null",
            client.toBlocking().retrieve(SimpleController.ECHO_BEAN));
    }

    @Test
    void echoRequestBean() {
        Assertions.assertEquals("42:active:v3",
            client.toBlocking().retrieve(
                HttpRequest.GET(SimpleController.ECHO_REQUEST_BEAN + "/42?filter=active")
                    .header("X-Version", "v3")));
    }

    @Test
    void echoRequestBeanOptionalFieldsAbsent() {
        Assertions.assertEquals("7:null:null",
            client.toBlocking().retrieve(
                SimpleController.ECHO_REQUEST_BEAN + "/7"));
    }

    @Test
    void echoNegotiatedWithValue() {
        Assertions.assertEquals("hello",
            client.toBlocking().retrieve(
                HttpRequest.GET(SimpleController.ECHO_NEGOTIATED + "?value=hello")
                    .accept(MediaType.TEXT_PLAIN_TYPE)));
    }

    @Test
    void echoNegotiatedEmpty() {
        Assertions.assertEquals("empty",
            client.toBlocking().retrieve(
                HttpRequest.GET(SimpleController.ECHO_NEGOTIATED)
                    .accept(MediaType.TEXT_PLAIN_TYPE)));
    }

    @Test
    void echoNegotiatedWithJson() {
        Assertions.assertEquals("hello",
            client.toBlocking().retrieve(
                HttpRequest.GET(SimpleController.ECHO_NEGOTIATED + "?value=hello")
                    .accept(MediaType.APPLICATION_JSON_TYPE)));
    }

    @Test
    void echoMultiAcceptJsonBody() {
        HttpResponse<String> response = client.toBlocking().exchange(
            HttpRequest.POST(SimpleController.ECHO_MULTI_ACCEPT, "{\"key\":\"val\"}")
                .accept(MediaType.TEXT_PLAIN_TYPE),
            String.class);
        Assertions.assertEquals(HttpStatus.OK, response.getStatus());
    }

    @Test
    void echoMultiAcceptFormBody() {
        HttpResponse<String> response = client.toBlocking().exchange(
            HttpRequest.POST(SimpleController.ECHO_MULTI_ACCEPT, "key=val")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.TEXT_PLAIN_TYPE),
            String.class);
        Assertions.assertEquals(HttpStatus.OK, response.getStatus());
    }

    @Test
    void uploadFile() {
        MultipartBody body = MultipartBody.builder()
            .addPart("file", "test.txt", MediaType.TEXT_PLAIN_TYPE, "hello".getBytes())
            .build();

        String response = client.toBlocking().retrieve(
            HttpRequest.POST(SimpleController.UPLOAD_FILE, body)
                .contentType(MediaType.MULTIPART_FORM_DATA_TYPE));

        Assertions.assertEquals("size:5", response);
    }

    @Test
    void uploadFileEmpty() {
        MultipartBody body = MultipartBody.builder()
            .addPart("file", "empty.txt", MediaType.TEXT_PLAIN_TYPE, new byte[0])
            .build();

        String response = client.toBlocking().retrieve(
            HttpRequest.POST(SimpleController.UPLOAD_FILE, body)
                .contentType(MediaType.MULTIPART_FORM_DATA_TYPE));

        Assertions.assertEquals("size:0", response);
    }

    @Test
    void uploadFields() {
        MultipartBody body = MultipartBody.builder()
            .addPart("username", "alice")
            .addPart("email", "alice@example.com")
            .build();

        String response = client.toBlocking().retrieve(
            HttpRequest.POST(SimpleController.UPLOAD_FIELDS, body)
                .contentType(MediaType.MULTIPART_FORM_DATA_TYPE));

        Assertions.assertEquals("alice/alice@example.com", response);
    }

    @Test
    void uploadMixed() {
        MultipartBody body = MultipartBody.builder()
            .addPart("name", "rapport")
            .addPart("data", "rapport.txt", MediaType.TEXT_PLAIN_TYPE, "contenu".getBytes())
            .build();

        String response = client.toBlocking().retrieve(
            HttpRequest.POST(SimpleController.UPLOAD_MIXED, body)
                .contentType(MediaType.MULTIPART_FORM_DATA_TYPE));

        Assertions.assertEquals("rapport:7", response);
    }

    @Test
    void uploadMultipleSingleFile() {
        MultipartBody body = MultipartBody.builder()
            .addPart("files", "only.txt", MediaType.TEXT_PLAIN_TYPE, "data".getBytes())
            .build();

        String response = client.toBlocking().retrieve(
            HttpRequest.POST(SimpleController.UPLOAD_MULTIPLE, body)
                .contentType(MediaType.MULTIPART_FORM_DATA_TYPE));


        Assertions.assertEquals("count:1", response);
    }

    @Test
    void echoSetCookieWithValue() {
        HttpResponse<String> response = client.toBlocking().exchange(
            HttpRequest.GET(SimpleController.ECHO_SET_COOKIE + "?value=hello"),
            String.class);
        Assertions.assertEquals(HttpStatus.OK, response.getStatus());
        String setCookie = response.header("Set-Cookie");
        Assertions.assertNotNull(setCookie, "Set-Cookie header must be present");
        Assertions.assertTrue(setCookie.contains("hello"), "cookie value must contain supplied string");
    }

    @Test
    void echoSetCookieDefaultWhenAbsent() {
        HttpResponse<String> response = client.toBlocking().exchange(
            HttpRequest.GET(SimpleController.ECHO_SET_COOKIE),
            String.class);
        Assertions.assertEquals(HttpStatus.OK, response.getStatus());
        String setCookie = response.header("Set-Cookie");
        Assertions.assertNotNull(setCookie);
        Assertions.assertTrue(setCookie.contains("default"));
    }

    @Test
    void echoMultiQueryTwoValues() {
        String body = client.toBlocking().retrieve(
            HttpRequest.GET(SimpleController.ECHO_MULTI_QUERY + "?tag=foo&tag=bar"));
        Assertions.assertEquals("foo,bar", body);
    }

    @Test
    void echoMultiQuerySingleValue() {
        String body = client.toBlocking().retrieve(
            HttpRequest.GET(SimpleController.ECHO_MULTI_QUERY + "?tag=only"));
        Assertions.assertEquals("only", body);
    }

    @Test
    void echoMultiQueryAbsent() {
        String body = client.toBlocking().retrieve(
            HttpRequest.GET(SimpleController.ECHO_MULTI_QUERY));
        Assertions.assertEquals("none", body);
    }

    @Test
    void echoJsonObjectRoundTrip() {
        String body = client.toBlocking().retrieve(
            HttpRequest.POST(SimpleController.ECHO_JSON_OBJECT,
                "{\"keyword\":\"micronaut\",\"page\":2,\"active\":true}")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON));
        Assertions.assertTrue(body.contains("micronaut"));
        Assertions.assertTrue(body.contains("2"));
    }

    @Test
    void echoJsonObjectEmptyBody() {
        HttpResponse<String> response = client.toBlocking().exchange(
            HttpRequest.POST(SimpleController.ECHO_JSON_OBJECT, "{}")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON),
            String.class);
        Assertions.assertEquals(HttpStatus.OK, response.getStatus());
    }

    @Test
    void echoJsonObjectNullFields() {
        String body = client.toBlocking().retrieve(
            HttpRequest.POST(SimpleController.ECHO_JSON_OBJECT,
                "{\"keyword\":null,\"page\":null,\"active\":null}")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON));
        Assertions.assertNotNull(body);
    }
}

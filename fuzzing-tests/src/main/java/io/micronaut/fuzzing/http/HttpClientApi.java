package io.micronaut.fuzzing.http;

import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.client.annotation.Client;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.concurrent.CompletionStage;

@Client("/")
public interface HttpClientApi extends Api {

    @Post(ECHO_PUBLISHER)
    Publisher<byte[]> echoPublisher(@Body byte[] foo);

    @SingleResult
    @Post(ECHO_STRING_PUBLISHER)
    Publisher<String> echoString(@Body String foo);

    @Post(ECHO_MONO)
    Mono<String> echoMono(@Body String foo);

    // Casting problem
    @Post(ECHO_MONO)
    Publisher<String> echoMonoPublisher(@Body String foo);

    @SingleResult
    @Post(ECHO_FLUX)
    Flux<String> echoFlux(@Body String foo);

    @Post(ECHO_FUTURE)
    CompletionStage<String> echoFuture(@Body String foo);

}

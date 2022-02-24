package io.micronaut.fuzzing.http;

import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
@Controller
public class SimpleController {
    private static final Logger LOG = LoggerFactory.getLogger(SimpleController.class);

    @Get
    public String index() {
        LOG.info("HIT! GET");
        return "index";
    }

    @Post
    public Publisher<String> index(Publisher<String> foo) {
        LOG.info("HIT! POST");
        return foo;
    }
}

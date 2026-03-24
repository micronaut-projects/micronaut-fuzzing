package io.micronaut.fuzzing.http;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.context.ApplicationContext;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.EmbeddedChannelFuzzerBase;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.micronaut.http.server.netty.NettyHttpServer;
import io.micronaut.runtime.server.EmbeddedServer;
import org.slf4j.LoggerFactory;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@FuzzTarget
@HttpDict
@Dict({

    SimpleController.ECHO_NEGOTIATED,
    SimpleController.ECHO_MULTI_ACCEPT,


    "Accept: application/json",
    "Accept: text/plain",
    "Accept: text/xml",
    "Accept: */*",
    "Accept: application/json;q=0.9,text/plain;q=0.8",

    "Accept: application/json;q=999",
    "Accept: application/json;q=-1",
    "Accept: a/b/c/d",
    "Accept: ",


    "Content-Type: application/json",
    "Content-Type: application/json; charset=utf-8",
    "Content-Type: ",
    "Content-Type: a/b/c",
    "Content-Type: application/json; charset=",


    "q=0.9", "q=1.0", "q=0", "q=",
})
public class ContentNegotiationFuzzTarget extends EmbeddedChannelFuzzerBase {

    private static final ContextHolder HTTP1 = new ContextHolder(Map.of());

    ContentNegotiationFuzzTarget(ContextHolder ctx) {
        super(ctx.nettyHttpServer.buildEmbeddedChannel(false));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        new ContentNegotiationFuzzTarget(HTTP1).fuzz(data);
    }

    private void fuzz(FuzzedDataProvider data) {


        int scenario = data.consumeInt(0, 3);

        String request;

        if (scenario == 0) {

            String accept = data.pickValue(new String[]{
                "application/json",
                "text/plain",
                "*/*",
                "application/json;q=0.9,text/plain;q=0.8",
                "application/json;q=999",
                "application/json;q=-1",
                "a/b/c/d",
                "",
                data.consumeString(100)
            });
            String value = data.consumeString(50);
            request =
                "GET /echo-negotiated?value=" + value + " HTTP/1.1\r\n" +
                "Host: localhost\r\n" +
                "Accept: " + accept + "\r\n" +
                "\r\n";

        } else if (scenario == 1) {

            String contentType = data.pickValue(new String[]{
                "application/json",
                "application/json; charset=utf-8",
                "application/x-www-form-urlencoded",
                "",
                "a/b/c",
                "application/json; q=abc",
                data.consumeString(80)
            });
            String body = data.consumeRemainingAsString();
            request =
                "POST /echo-multi-accept HTTP/1.1\r\n" +
                "Host: localhost\r\n" +
                "Content-Type: " + contentType + "\r\n" +
                "Content-Length: " + body.length() + "\r\n" +
                "\r\n" + body;

        } else if (scenario == 2) {
            String accept = data.consumeString(100);
            String contentType = data.consumeString(80);
            String body = data.consumeRemainingAsString();
            request =
                "POST /echo-multi-accept HTTP/1.1\r\n" +
                "Host: localhost\r\n" +
                "Accept: " + accept + "\r\n" +
                "Content-Type: " + contentType + "\r\n" +
                "Content-Length: " + body.length() + "\r\n" +
                "\r\n" + body;

        } else {
            StringBuilder accept = new StringBuilder();
            int count = data.consumeInt(5, 50);
            for (int i = 0; i < count; i++) {
                if (i > 0) accept.append(",");
                accept.append(data.consumeString(20));
                accept.append(";q=");
                accept.append(data.consumeString(5));
            }
            request =
                "GET /echo-negotiated HTTP/1.1\r\n" +
                "Host: localhost\r\n" +
                "Accept: " + accept + "\r\n" +
                "\r\n";
        }

        test(request.getBytes(StandardCharsets.ISO_8859_1));
    }

    private void test(byte[] bytes) {
        try {
            channel.writeInbound(io.netty.buffer.Unpooled.wrappedBuffer(bytes));
            channel.finish();
            channel.releaseOutbound();
        } catch (Exception e) {
            onException(e);
        }
    }


    static void main(String[] args) {
        LocalJazzerRunner.create(ContentNegotiationFuzzTarget.class)
            .reproduce(
                "POST /echo-multi-accept HTTP/1.1\r\nHost: localhost\r\nContent-Type: \r\nContent-Length: 0\r\n\r\n"
                .getBytes(StandardCharsets.UTF_8)
            );
    }

    static final class ContextHolder {
        final NettyHttpServer nettyHttpServer;
        ContextHolder(Map<String, Object> cfg) {
            String vmName = ManagementFactory.getRuntimeMXBean().getName();
            System.setProperty("VM_NAME", vmName);
            LoggerFactory.getLogger(ContentNegotiationFuzzTarget.class)
                .info("Starting content negotiation fuzz target. VM: {}", vmName);
            ApplicationContext ctx = ApplicationContext.run(cfg);
            nettyHttpServer = (NettyHttpServer) ctx.getBean(EmbeddedServer.class);
        }
    }
}

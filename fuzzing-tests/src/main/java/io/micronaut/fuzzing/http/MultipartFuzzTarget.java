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
    "multipart/form-data; boundary=",
    "Content-Disposition: form-data; name=\"",
    "Content-Disposition: form-data; name=\"file\"; filename=\"",
    "Content-Type: application/octet-stream",
    "Content-Type: image/jpeg",
    "Content-Type: text/plain",
    "--boundary",
    "--boundary--",
    "\r\n\r\n",
    SimpleController.UPLOAD_FILE,
    SimpleController.UPLOAD_FIELDS,
    SimpleController.UPLOAD_MIXED,
})
public class MultipartFuzzTarget extends EmbeddedChannelFuzzerBase {

    private static final ContextHolder HTTP1 = new ContextHolder(Map.of());

    MultipartFuzzTarget(ContextHolder ctx) {
        super(ctx.nettyHttpServer.buildEmbeddedChannel(false));
        this.inputCpuTime = 50;
        this.baseCpuTime = 1_000_000;
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String boundary = sanitizeBoundary(data.consumeString(40));
        int partCount = data.consumeInt(1, 5);
        String path = data.pickValue(new String[]{
            SimpleController.UPLOAD_FILE,
            SimpleController.UPLOAD_FIELDS,
            SimpleController.UPLOAD_MIXED,
            "/" + data.consumeString(30)
        });
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < partCount; i++) {
            String partBoundary = data.consumeBoolean() ? boundary : data.consumeString(20);
            body.append("--").append(partBoundary).append("\r\n");
            String partName = data.consumeString(20);
            boolean isFile = data.consumeBoolean();
            if (isFile) {
                String filename = data.consumeString(30);
                body.append("Content-Disposition: form-data; name=\"").append(partName).append("\"; filename=\"").append(filename).append("\"\r\n");
                String ct = data.pickValue(new String[]{"image/jpeg","application/octet-stream","text/plain",data.consumeString(30)});
                body.append("Content-Type: ").append(ct).append("\r\n");
            } else {
                body.append("Content-Disposition: form-data; name=\"").append(partName).append("\"\r\n");
            }
            body.append("\r\n");
            String content = data.consumeBoolean() ? data.consumeRemainingAsString() : "--" + boundary + data.consumeString(10);
            body.append(content).append("\r\n");
        }
        body.append("--").append(boundary).append("--\r\n");
        String bodyStr = body.toString();
        byte[] bodyBytes = bodyStr.getBytes(StandardCharsets.ISO_8859_1);
        String request = "POST " + path + " HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data; boundary=" + boundary + "\r\nContent-Length: " + bodyBytes.length + "\r\n\r\n" + bodyStr;
        new MultipartFuzzTarget(HTTP1).testBytes(request.getBytes(StandardCharsets.ISO_8859_1));
    }

    void testBytes(byte[] bytes) {
        try {
            channel.writeInbound(io.netty.buffer.Unpooled.wrappedBuffer(bytes));
            channel.finish();
            channel.releaseOutbound();
        } catch (Exception e) {
            onException(e);
        }
    }

    private static String sanitizeBoundary(String raw) {
        if (raw == null || raw.isEmpty()) return "fuzzBoundary";
        String clean = raw.replaceAll("[^a-zA-Z0-9'()+_,-./:=?]", "x");
        return clean.isEmpty() ? "fuzzBoundary" : clean;
    }

    @Override
    protected void onException(Exception e) {
        String msg = e.getMessage();
        if (msg != null && (msg.contains("Invalid boundary") || msg.contains("Request body limit") || msg.contains("Content-Disposition"))) return;
        super.onException(e);
    }

    static void main(String[] args) {
        LocalJazzerRunner.create(MultipartFuzzTarget.class).reproduce(("POST /upload-file HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data; boundary=fuzzBoundary\r\nContent-Length: 150\r\n\r\n--fuzzBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nFAKEJPEGDATA\r\n--fuzzBoundary--\r\n").getBytes(StandardCharsets.UTF_8));
    }

    static final class ContextHolder {
        final NettyHttpServer nettyHttpServer;
        ContextHolder(Map<String, Object> cfg) {
            String vmName = ManagementFactory.getRuntimeMXBean().getName();
            System.setProperty("VM_NAME", vmName);
            LoggerFactory.getLogger(MultipartFuzzTarget.class).info("Starting multipart fuzz target. VM: {}", vmName);
            ApplicationContext ctx = ApplicationContext.run(cfg);
            nettyHttpServer = (NettyHttpServer) ctx.getBean(EmbeddedServer.class);
        }
    }
}

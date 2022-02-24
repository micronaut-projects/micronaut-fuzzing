package io.micronaut.fuzzing.http;

import io.micronaut.context.ApplicationContext;
import io.micronaut.fuzzing.FlagAppender;
import io.micronaut.http.server.netty.NettyHttpServer;
import io.micronaut.runtime.server.EmbeddedServer;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.LoggerFactory;

import java.lang.management.ManagementFactory;

public class EmbeddedHttpTarget {
    private static NettyHttpServer nettyHttpServer;

    public static void fuzzerInitialize() {
        System.setProperty("io.netty.leakDetection.level", "paranoid");
        System.setProperty("io.netty.leakDetection.targetRecords", "100");

        String vmName = ManagementFactory.getRuntimeMXBean().getName();
        System.setProperty("VM_NAME", vmName);
        LoggerFactory.getLogger(EmbeddedHttpTarget.class).info("Starting embedded HTTP target. VM name is: {}", vmName);
        CustomResourceLeakDetector.register();

        ApplicationContext ctx = ApplicationContext.run();

        nettyHttpServer = (NettyHttpServer) ctx.getBean(EmbeddedServer.class);
    }

    public static void fuzzerTestOneInput(byte[] input) {
        CustomResourceLeakDetector.setCurrentInput(input);

        EmbeddedChannel embeddedChannel = nettyHttpServer.buildEmbeddedChannel(false);

        embeddedChannel.writeOneInbound(Unpooled.wrappedBuffer(input));
        embeddedChannel.runPendingTasks();

        embeddedChannel.releaseOutbound();
        // don't release inbound, that doesn't happen normally either
        for (Object inboundMessage : embeddedChannel.inboundMessages()) {
            ReferenceCountUtil.touch(inboundMessage);
        }
        embeddedChannel.finish();

        embeddedChannel.checkException();

        CustomResourceLeakDetector.reportLeaks();
        CustomResourceLeakDetector.reportStillOpen();
        FlagAppender.checkTriggered();
    }

    public static void fuzzerTearDown() {
        //CustomResourceLeakDetector.reportStillOpen();
    }
}

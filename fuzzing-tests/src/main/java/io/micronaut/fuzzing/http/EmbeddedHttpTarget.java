/*
 * Copyright 2017-2024 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.fuzzing.http;

import io.micronaut.context.ApplicationContext;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.FlagAppender;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.http.server.netty.NettyHttpServer;
import io.micronaut.runtime.server.EmbeddedServer;
import io.netty.buffer.ByteBuf;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.LoggerFactory;

import java.lang.management.ManagementFactory;

@FuzzTarget
@HttpDict
@Dict({
    ByteSeparator.SEPARATOR,
    SimpleController.ECHO_ARRAY,
    SimpleController.ECHO_PUBLISHER,
    SimpleController.ECHO_STRING,
    SimpleController.ECHO_PIECE_JSON,
})
public class EmbeddedHttpTarget {
    private static NettyHttpServer nettyHttpServer;

    public static void fuzzerInitialize() {
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

        ByteBuf joint = embeddedChannel.alloc().buffer(input.length);
        joint.writeBytes(input);
        ByteSeparator.forEachPiece(joint, msg -> {
            if (embeddedChannel.isOpen()) {
                embeddedChannel.writeInbound(msg);
            } else {
                msg.release();
            }
        });

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

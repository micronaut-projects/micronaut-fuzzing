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
import io.micronaut.core.annotation.NonNull;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.http.netty.channel.EventLoopGroupConfiguration;
import io.micronaut.http.netty.channel.EventLoopGroupRegistry;
import io.micronaut.runtime.server.EmbeddedServer;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.resolver.NoopAddressResolverGroup;
import org.slf4j.LoggerFactory;

import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@FuzzTarget(enableImplicitly = false) // we prefer EmbeddedHttpTarget for now
@HttpDict
public class HttpTarget {
    private static EmbeddedServer embeddedServer;
    private static Bootstrap clientBootstrap;

    public static void fuzzerInitialize() {
        System.setProperty("io.netty.leakDetection.level", "paranoid");
        System.setProperty("io.netty.leakDetection.targetRecords", "100");

        String vmName = ManagementFactory.getRuntimeMXBean().getName();
        System.setProperty("VM_NAME", vmName);
        LoggerFactory.getLogger(HttpTarget.class).info("Starting HTTP target. VM name is: {}", vmName);
        CustomResourceLeakDetector.register();

        ApplicationContext ctx = ApplicationContext.run(Map.of(
                "micronaut.server.port", "-1",
                "micronaut.netty.event-loops.default.num-threads", "1"
        ));

        embeddedServer = ctx.getBean(EmbeddedServer.class);
        embeddedServer.start();

        //noinspection OptionalGetWithoutIsPresent
        clientBootstrap = new Bootstrap()
                .remoteAddress(new InetSocketAddress(embeddedServer.getHost(), embeddedServer.getPort()))
                .resolver(NoopAddressResolverGroup.INSTANCE)
                .group(ctx.getBean(EventLoopGroupRegistry.class).getEventLoopGroup(EventLoopGroupConfiguration.DEFAULT).get())
                .channel(NioSocketChannel.class)
                .option(ChannelOption.AUTO_READ, true)
                .handler(new ChannelInitializer<>() {
                    @Override
                    protected void initChannel(@NonNull Channel ch) {
                        ch.pipeline()
                                .addLast(new ReadTimeoutHandler(500, TimeUnit.MILLISECONDS))
                                .addLast(BlackholeInboundHandler.INSTANCE);
                    }
                });
    }

    public static void main(String[] args) throws Exception {
        fuzzerInitialize();
        try {
            fuzzerTestOneInput("GET / HTTP/1.1\r\nContent-Length: 0\r\nHost: localhost\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.UTF_8));
        } finally {
            fuzzerTearDown();
        }
    }

    public static void fuzzerTestOneInput(byte[] input) throws Exception {
        CustomResourceLeakDetector.setCurrentInput(input);

        Channel channel = clientBootstrap.connect().sync().channel();
        channel.writeAndFlush(Unpooled.wrappedBuffer(input));
        channel.closeFuture().await();

        CustomResourceLeakDetector.reportLeaks();
    }

    public static void fuzzerTearDown() {
        embeddedServer.close();

        CustomResourceLeakDetector.reportStillOpen();
    }
}

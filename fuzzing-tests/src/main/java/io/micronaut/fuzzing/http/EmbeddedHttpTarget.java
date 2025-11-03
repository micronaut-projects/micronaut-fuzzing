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
    SimpleController.ECHO_ARRAY,
    SimpleController.ECHO_PUBLISHER,
    SimpleController.ECHO_STRING,
    SimpleController.ECHO_PIECE_JSON,

    SimpleController.ECHO_STRING_PUBLISHER,
    SimpleController.ECHO_MONO,
    SimpleController.ECHO_FLUX,
    SimpleController.ECHO_FUTURE,
    RedirectingController.REDIRECT_PUBLISHER,
    RedirectingController.REDIRECT_STRING_PUBLISHER,
    RedirectingController.REDIRECT_MONO,
    RedirectingController.REDIRECT_FLUX,
    RedirectingController.REDIRECT_FUTURE,
    RedirectingController.REDIRECT_ARRAY,
    RedirectingController.REDIRECT_STRING,

})
public class EmbeddedHttpTarget extends EmbeddedChannelFuzzerBase {
    private static final ContextHolder HTTP1 = new ContextHolder(Map.of());

    EmbeddedHttpTarget(ContextHolder contextHolder) {
        super(contextHolder.nettyHttpServer.buildEmbeddedChannel(false));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider input) {
        new EmbeddedHttpTarget(HTTP1).test(input);
    }

    static void main(String[] args) {
        LocalJazzerRunner.create(EmbeddedHttpTarget.class).reproduce("GET / HTTP/1.1\r\nContent-Length: 0\r\nHost: localhost\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.UTF_8));
    }

    static final class ContextHolder {
        final NettyHttpServer nettyHttpServer;

        ContextHolder(Map<String, Object> cfg) {
            String vmName = ManagementFactory.getRuntimeMXBean().getName();
            System.setProperty("VM_NAME", vmName);
            LoggerFactory.getLogger(EmbeddedHttpTarget.class).info("Starting embedded HTTP target. VM name is: {}", vmName);

            ApplicationContext ctx = ApplicationContext.run(cfg);

            nettyHttpServer = (NettyHttpServer) ctx.getBean(EmbeddedServer.class);
        }
    }
}

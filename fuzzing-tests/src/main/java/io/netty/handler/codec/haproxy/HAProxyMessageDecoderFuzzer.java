/*
 * Copyright 2017-2026 original authors
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
package io.netty.handler.codec.haproxy;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.DictResource;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.HandlerFuzzerBase;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Fuzzes {@link HAProxyMessageDecoder} with PROXY protocol v1 and v2 input. The decoder must produce at most one
 * message, and none after an exception. Every decoded message is encoded with {@link HAProxyMessageEncoder} and
 * decoded again, and the result must be equal to the original message.
 */
@FuzzTarget
@DictResource("dictionaries/haproxy.dict")
public class HAProxyMessageDecoderFuzzer extends HandlerFuzzerBase {
    /**
     * Methods that throw an {@link IllegalArgumentException} for invalid input, which {@link HAProxyMessage} wraps
     * in a {@link HAProxyProtocolException}.
     */
    private static final Set<String> VALIDATION_METHODS = Set.of("valueOf", "checkAddress", "checkPort", "portStringToInt");

    private final int constructor;
    private final int maxTlvSize;
    private final boolean failFast;

    public HAProxyMessageDecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        constructor = fuzzedDataProvider.consumeInt(0, 3);
        // small values limit the header size, the full range covers negative and too large values
        maxTlvSize = fuzzedDataProvider.consumeBoolean() ? fuzzedDataProvider.consumeInt(-1, 1024) : fuzzedDataProvider.consumeInt();
        failFast = fuzzedDataProvider.consumeBoolean();
    }

    @Override
    protected EmbeddedChannel setUp() {
        HAProxyMessageDecoder decoder = switch (constructor) {
            case 0 -> new HAProxyMessageDecoder();
            case 1 -> new HAProxyMessageDecoder(failFast);
            case 2 -> new HAProxyMessageDecoder(maxTlvSize);
            default -> new HAProxyMessageDecoder(maxTlvSize, failFast);
        };
        return new EmbeddedChannel(decoder, new RoundTripChecker());
    }

    @Override
    protected void onException(Exception e) {
        if (isExpected(e)) {
            return;
        }
        super.onException(e);
    }

    /**
     * The decoder reports invalid input with a {@link HAProxyProtocolException}. {@link HAProxyMessage} wraps the
     * {@link IllegalArgumentException}s of its validation methods, but also any other {@link RuntimeException} of the
     * {@link HAProxyMessage} constructor, so only accept causes thrown by the validation methods.
     */
    static boolean isExpected(Throwable t) {
        if (!(t instanceof HAProxyProtocolException)) {
            return false;
        }
        Throwable cause = t.getCause();
        if (cause == null) {
            return true;
        }
        if (cause instanceof HAProxyProtocolException) {
            return isExpected(cause);
        }
        return cause.getClass() == IllegalArgumentException.class && isThrownByValidation(cause.getStackTrace());
    }

    /**
     * Whether the exception was thrown by one of the validation methods, or by {@link Enum#valueOf} called from the
     * {@code valueOf(String)} method of an enum of this package.
     */
    private static boolean isThrownByValidation(StackTraceElement[] stackTrace) {
        if (stackTrace.length == 0) {
            return false;
        }
        StackTraceElement thrower = stackTrace[0];
        if (thrower.getClassName().equals(Enum.class.getName()) && thrower.getMethodName().equals("valueOf")) {
            return stackTrace.length > 1 && isNettyFrame(stackTrace[1]) && stackTrace[1].getMethodName().equals("valueOf");
        }
        return isNettyFrame(thrower) && VALIDATION_METHODS.contains(thrower.getMethodName());
    }

    /**
     * Whether the frame is in a Netty class of this package, i.e. not in this fuzzer or its test.
     */
    private static boolean isNettyFrame(StackTraceElement element) {
        String className = element.getClassName();
        return className.startsWith(HAProxyMessage.class.getPackageName() + ".")
            && !className.startsWith(HAProxyMessageDecoderFuzzer.class.getName());
    }

    /**
     * Encodes a decoded message and decodes it again. The decoder must produce an equal message from the encoded
     * bytes, and nothing else.
     */
    static void checkRoundTrip(HAProxyMessage message) throws Exception {
        ByteBuf encoded = ByteBufAllocator.DEFAULT.buffer();
        try {
            HAProxyMessageEncoder.INSTANCE.encode(null, message, encoded);
        } catch (Exception e) {
            encoded.release();
            throw new AssertionError("Failed to encode " + message, e);
        }
        EmbeddedChannel channel = new EmbeddedChannel(new HAProxyMessageDecoder());
        Throwable failure = null;
        try {
            checkDecodesTo(channel, encoded, message);
        } catch (Throwable t) {
            failure = t;
            throw t;
        } finally {
            try {
                channel.finishAndReleaseAll();
            } catch (Throwable t) {
                if (failure == null) {
                    throw t;
                }
                failure.addSuppressed(t);
            }
        }
    }

    private static void checkDecodesTo(EmbeddedChannel channel, ByteBuf encoded, HAProxyMessage original) {
        try {
            channel.writeInbound(encoded);
        } catch (Exception e) {
            throw new AssertionError("Failed to decode re-encoded " + describe(original), e);
        }
        HAProxyMessage decoded = channel.readInbound();
        if (decoded == null) {
            throw new AssertionError("No message decoded from re-encoded " + describe(original));
        }
        try {
            if (!channel.inboundMessages().isEmpty()) {
                throw new AssertionError("Re-encoded " + describe(original) + " decoded to more than one message");
            }
            if (!messagesEqual(original, decoded)) {
                throw new AssertionError("Round trip mismatch: " + describe(original) + " was re-decoded as " + decoded);
            }
        } finally {
            decoded.release();
        }
    }

    /**
     * Describes a message and its encoding, for failures only.
     */
    private static String describe(HAProxyMessage message) {
        ByteBuf encoded = ByteBufAllocator.DEFAULT.buffer();
        try {
            HAProxyMessageEncoder.INSTANCE.encode(null, message, encoded);
            return message + " (encoded as " + ByteBufUtil.hexDump(encoded) + ")";
        } catch (Exception e) {
            return message.toString();
        } finally {
            encoded.release();
        }
    }

    private static boolean messagesEqual(HAProxyMessage original, HAProxyMessage decoded) {
        return original.protocolVersion() == decoded.protocolVersion()
            && original.command() == decoded.command()
            && original.proxiedProtocol() == decoded.proxiedProtocol()
            && Objects.equals(original.sourceAddress(), decoded.sourceAddress())
            && Objects.equals(original.destinationAddress(), decoded.destinationAddress())
            && original.sourcePort() == decoded.sourcePort()
            && original.destinationPort() == decoded.destinationPort()
            && tlvsEqual(topLevelTlvs(original), topLevelTlvs(decoded));
    }

    /**
     * {@link HAProxyMessage#tlvs()} also contains the direct children of each SSL TLV. Remove them, they are
     * compared as part of their parent.
     */
    private static List<HAProxyTLV> topLevelTlvs(HAProxyMessage message) {
        List<HAProxyTLV> tlvs = message.tlvs();
        List<HAProxyTLV> topLevel = new ArrayList<>(tlvs.size());
        for (int i = 0; i < tlvs.size(); i += 1 + HAProxyMessage.flattenedChildren(tlvs, i)) {
            topLevel.add(tlvs.get(i));
        }
        return topLevel;
    }

    private static boolean tlvsEqual(List<HAProxyTLV> original, List<HAProxyTLV> decoded) {
        if (decoded.size() != original.size()) {
            return false;
        }
        for (int i = 0; i < decoded.size(); i++) {
            if (!tlvEqual(original.get(i), decoded.get(i))) {
                return false;
            }
        }
        return true;
    }

    private static boolean tlvEqual(HAProxyTLV original, HAProxyTLV decoded) {
        if (original.type() != decoded.type() || original.typeByteValue() != decoded.typeByteValue()) {
            return false;
        }
        if (original instanceof HAProxySSLTLV sslOriginal && decoded instanceof HAProxySSLTLV sslDecoded) {
            // the raw content of a decoded SSL TLV includes trailing bytes after the last sub-TLV, which the
            // encoder drops, so compare the parsed fields instead
            return sslOriginal.client() == sslDecoded.client()
                && sslOriginal.verify() == sslDecoded.verify()
                && tlvsEqual(sslOriginal.encapsulatedTLVs(), sslDecoded.encapsulatedTLVs());
        }
        return !(original instanceof HAProxySSLTLV) && !(decoded instanceof HAProxySSLTLV)
            && ByteBufUtil.equals(original.content(), decoded.content());
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        new HAProxyMessageDecoderFuzzer(fuzzedDataProvider).test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HAProxyMessageDecoderFuzzer.class).fuzz();
    }

    /**
     * Checks every decoded message with {@link #checkRoundTrip}, and that the decoder produces at most one message,
     * and none after an exception.
     */
    static final class RoundTripChecker extends ChannelInboundHandlerAdapter {
        private boolean decoded;
        private boolean failed;

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
            if (msg instanceof HAProxyMessage message) {
                try {
                    if (decoded || failed) {
                        throw new AssertionError("Decoded " + message + (failed ? " after an exception" : " after another message"));
                    }
                    decoded = true;
                    checkRoundTrip(message);
                } catch (Throwable t) {
                    message.release();
                    throw t;
                }
            }
            ctx.fireChannelRead(msg);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            failed = true;
            ctx.fireExceptionCaught(cause);
        }
    }
}

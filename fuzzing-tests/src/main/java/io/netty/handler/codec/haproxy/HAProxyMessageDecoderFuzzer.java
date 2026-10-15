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
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.DecoderException;

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
        if (isExpected(e) || isKnownRelativeHeaderEndBug(e) || isKnownTlvLengthBug(e)) {
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
     * Known Netty bug: for v2 headers, {@code HAProxyMessageDecoder.findEndOfHeader} returns the header length
     * relative to the reader index, but {@code HeaderExtractor.extract} treats it as an absolute index. With a
     * non-zero reader index, e.g. when the decoder decodes the remaining bytes after a failure (see
     * {@link #isKnownDecodeAfterFinishedBug()}), {@code readSlice} throws an {@link IllegalArgumentException} for the
     * negative length.
     * <p>
     * Fixed by https://github.com/netty/netty/pull/17832, remove this once it is released.
     */
    static boolean isKnownRelativeHeaderEndBug(Throwable t) {
        return isWrappedFrom(t, IllegalArgumentException.class, "readSlice",
            HAProxyMessageDecoder.class.getName() + "$HeaderExtractor", "extract");
    }

    /**
     * Known Netty bug: {@code HAProxyMessage.readNextTLV} does not check the length of a TLV that is not of type
     * {@code PP2_TYPE_SSL} against the remaining header, so {@code readRetainedSlice} throws an
     * {@link IndexOutOfBoundsException} instead of a {@link HAProxyProtocolException}, and the decoder does not close
     * the channel.
     * <p>
     * Fixed by https://github.com/netty/netty/pull/17834, remove this once it is released.
     */
    static boolean isKnownTlvLengthBug(Throwable t) {
        return isWrappedFrom(t, IndexOutOfBoundsException.class, "readRetainedSlice",
            HAProxyMessage.class.getName(), "readNextTLV");
    }

    /**
     * Known Netty bug: {@code HAProxyMessageDecoder.decode} does not check whether the decoder already decoded a
     * header or failed. When the channel is closed, {@code ByteToMessageDecoder.channelInputClosed} decodes the
     * remaining bytes, which can produce another message after the first one or after a failure.
     * <p>
     * Fixed by https://github.com/netty/netty/pull/17832, remove this once it is released.
     */
    static boolean isKnownDecodeAfterFinishedBug() {
        return StackWalker.getInstance().walk(frames -> frames.anyMatch(frame ->
            frame.getClassName().equals(ByteToMessageDecoder.class.getName())
                && frame.getMethodName().equals("channelInputClosed")));
    }

    /**
     * Known Netty bug: {@code HAProxyMessageEncoder.encodeV1} writes the addresses of a "PROXY UNKNOWN" message,
     * which are null, and throws a {@link NullPointerException}. The JIT omits the stack trace of this implicit
     * exception once it is thrown often, so also accept an exception without one.
     * <p>
     * Fixed by https://github.com/netty/netty/pull/17837, remove this once it is released.
     */
    static boolean isKnownV1UnknownEncoderBug(HAProxyMessage message, Throwable t) {
        if (message.protocolVersion() != HAProxyProtocolVersion.V1
            || message.proxiedProtocol() != HAProxyProxiedProtocol.UNKNOWN
            || t.getClass() != NullPointerException.class) {
            return false;
        }
        if (t.getStackTrace().length == 0) {
            return true;
        }
        StackTraceElement thrower = firstNettyFrame(t);
        return thrower != null
            && thrower.getClassName().equals(HAProxyMessageEncoder.class.getName())
            && thrower.getMethodName().equals("encodeV1");
    }

    /**
     * Whether {@code t} is the {@link DecoderException} of {@code ByteToMessageDecoder} wrapping an exception of
     * exactly the given type, thrown by the given {@code ByteBuf} method called from the given decoder method.
     */
    private static boolean isWrappedFrom(Throwable t, Class<?> causeType, String bufferMethod, String className, String methodName) {
        if (t.getClass() != DecoderException.class || t.getCause() == null || t.getCause().getClass() != causeType) {
            return false;
        }
        StackTraceElement[] stackTrace = t.getCause().getStackTrace();
        for (int i = 1; i < stackTrace.length; i++) {
            if (isNettyFrame(stackTrace[i])) {
                return stackTrace[i].getClassName().equals(className)
                    && stackTrace[i].getMethodName().equals(methodName)
                    && stackTrace[i - 1].getMethodName().equals(bufferMethod);
            }
        }
        return false;
    }

    private static StackTraceElement firstNettyFrame(Throwable t) {
        for (StackTraceElement element : t.getStackTrace()) {
            if (isNettyFrame(element)) {
                return element;
            }
        }
        return null;
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
            if (isKnownV1UnknownEncoderBug(message, e)) {
                return;
            }
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
        boolean lastLost = decoded.size() == original.size() - 1 && isKnownEmptyLastTlvBug(original.get(original.size() - 1));
        if (decoded.size() != original.size() && !lastLost) {
            return false;
        }
        for (int i = 0; i < decoded.size(); i++) {
            if (!tlvEqual(original.get(i), decoded.get(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Known Netty bug: {@code HAProxyMessage.readNextTLV} needs 4 readable bytes for a TLV, but the TLV header is
     * only 3 bytes long, so it ignores a TLV with an empty value at the end of the header or of an SSL TLV. The
     * decoder only reads such a TLV when other bytes follow it, which the encoder does not write, so the TLV may be
     * lost in the round trip.
     * <p>
     * Fixed by https://github.com/netty/netty/pull/17835, remove this once it is released.
     */
    private static boolean isKnownEmptyLastTlvBug(HAProxyTLV tlv) {
        return !(tlv instanceof HAProxySSLTLV) && !tlv.content().isReadable();
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
                    if ((decoded || failed) && !isKnownDecodeAfterFinishedBug()) {
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

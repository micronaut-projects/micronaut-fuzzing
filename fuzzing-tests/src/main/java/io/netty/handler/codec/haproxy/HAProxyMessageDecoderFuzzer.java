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
import io.netty.handler.codec.DecoderException;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Fuzzes {@link HAProxyMessageDecoder} with PROXY protocol v1 and v2 input. Every decoded message is encoded with
 * {@link HAProxyMessageEncoder} and decoded again, and the result must be equal to the original message.
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
        if (cause.getClass() != IllegalArgumentException.class) {
            return false;
        }
        StackTraceElement thrower = firstHAProxyFrame(cause);
        return thrower != null && VALIDATION_METHODS.contains(thrower.getMethodName());
    }

    /**
     * Known Netty bug: for v2 headers, {@code HAProxyMessageDecoder.findEndOfHeader} returns the header length
     * relative to the reader index, but {@code HeaderExtractor.extract} treats it as an absolute index. After a
     * failure (e.g. a header that exceeds the maximum length), the decoder keeps decoding the remaining bytes when
     * the channel is closed, with a non-zero reader index, and {@code readSlice} throws an
     * {@link IllegalArgumentException} for the negative length.
     * TODO: link the upstream fix and remove this once it is released.
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
     * TODO: link the upstream fix and remove this once it is released.
     */
    static boolean isKnownTlvLengthBug(Throwable t) {
        return isWrappedFrom(t, IndexOutOfBoundsException.class, "readRetainedSlice",
            HAProxyMessage.class.getName(), "readNextTLV");
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
            if (isHAProxyFrame(stackTrace[i])) {
                return stackTrace[i].getClassName().equals(className)
                    && stackTrace[i].getMethodName().equals(methodName)
                    && stackTrace[i - 1].getMethodName().equals(bufferMethod);
            }
        }
        return false;
    }

    private static StackTraceElement firstHAProxyFrame(Throwable t) {
        for (StackTraceElement element : t.getStackTrace()) {
            if (isHAProxyFrame(element)) {
                return element;
            }
        }
        return null;
    }

    private static boolean isHAProxyFrame(StackTraceElement element) {
        return element.getClassName().startsWith(HAProxyMessage.class.getPackageName() + ".");
    }

    /**
     * Encodes a decoded message and decodes it again. The decoder must produce an equal message from the encoded
     * bytes, and nothing else.
     */
    static void checkRoundTrip(HAProxyMessage message) throws Exception {
        if (message.protocolVersion() == HAProxyProtocolVersion.V1 && message.proxiedProtocol() == HAProxyProxiedProtocol.UNKNOWN) {
            // HAProxyMessageEncoder cannot encode "PROXY UNKNOWN": it writes the null addresses and throws an NPE.
            return;
        }
        ByteBuf encoded = ByteBufAllocator.DEFAULT.buffer();
        try {
            HAProxyMessageEncoder.INSTANCE.encode(null, message, encoded);
        } catch (Exception e) {
            encoded.release();
            throw new AssertionError("Failed to encode " + message, e);
        }
        EmbeddedChannel channel = new EmbeddedChannel(new HAProxyMessageDecoder());
        try {
            String hex = ByteBufUtil.hexDump(encoded);
            try {
                channel.writeInbound(encoded);
            } catch (Exception e) {
                throw new AssertionError("Failed to decode re-encoded " + message + ": " + hex, e);
            }
            HAProxyMessage decoded = channel.readInbound();
            if (decoded == null) {
                throw new AssertionError("No message decoded from re-encoded " + message + ": " + hex);
            }
            try {
                if (!channel.inboundMessages().isEmpty()) {
                    throw new AssertionError("Re-encoded " + message + " decoded to more than one message: " + hex);
                }
                if (!messagesEqual(message, decoded)) {
                    throw new AssertionError("Round trip mismatch: " + message + " was re-decoded as " + decoded + " from " + hex);
                }
            } finally {
                decoded.release();
            }
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    private static boolean messagesEqual(HAProxyMessage original, HAProxyMessage decoded) {
        return original.protocolVersion() == decoded.protocolVersion()
            && original.command() == decoded.command()
            && original.proxiedProtocol() == decoded.proxiedProtocol()
            && Objects.equals(normalizeAddress(original.sourceAddress()), decoded.sourceAddress())
            && Objects.equals(normalizeAddress(original.destinationAddress()), decoded.destinationAddress())
            && original.sourcePort() == decoded.sourcePort()
            && original.destinationPort() == decoded.destinationPort()
            && tlvsEqual(topLevelTlvs(original), topLevelTlvs(decoded));
    }

    /**
     * The decoder replaces non-ASCII bytes of a v2 AF_UNIX address with U+FFFD, which the encoder writes as '?'.
     */
    private static String normalizeAddress(String address) {
        return address == null ? null : address.replace('\uFFFD', '?');
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
        int expectedSize = original.size();
        if (expectedSize > 0 && isKnownEmptyLastTlvBug(original.get(expectedSize - 1))) {
            expectedSize--;
        }
        if (decoded.size() != expectedSize) {
            return false;
        }
        for (int i = 0; i < expectedSize; i++) {
            if (!tlvEqual(original.get(i), decoded.get(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Known Netty bug: {@code HAProxyMessage.readNextTLV} needs 4 readable bytes for a TLV, but the TLV header is
     * only 3 bytes long, so it ignores a TLV with an empty value at the end of the header or of an SSL TLV. The
     * decoder only reads such a TLV when other bytes follow it, which the encoder does not write, so the TLV is lost
     * in the round trip.
     * TODO: link the upstream fix and remove this once it is released.
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

    private static final class RoundTripChecker extends ChannelInboundHandlerAdapter {
        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
            if (msg instanceof HAProxyMessage message) {
                try {
                    checkRoundTrip(message);
                } catch (Throwable t) {
                    message.release();
                    throw t;
                }
            }
            ctx.fireChannelRead(msg);
        }
    }
}

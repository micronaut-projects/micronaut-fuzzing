/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package net.jpountz.fuzz;

import io.micronaut.fuzzing.sanitizer.SanitizerTransformer;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

final class Lz4ByteBufFuzzingSupport {
    static final int MAX_INPUT_SIZE = 4096;
    static final int MAX_OUTPUT_SIZE = 8192;

    static {
        SanitizerTransformer.installLocally();
    }

    private Lz4ByteBufFuzzingSupport() {
    }

    static ByteBuf buffer(byte[] bytes) {
        ByteBuf backing = Unpooled.buffer(bytes.length + 32, bytes.length + 32);
        backing.writeZero(16);
        backing.writeBytes(bytes);
        backing.writeZero(16);
        return backing.slice(16, bytes.length);
    }
}

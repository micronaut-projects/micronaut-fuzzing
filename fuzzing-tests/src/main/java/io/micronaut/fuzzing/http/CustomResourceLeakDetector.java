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

import io.netty.util.ResourceLeakDetector;
import io.netty.util.ResourceLeakDetectorFactory;
import io.netty.util.ResourceLeakHint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

final class CustomResourceLeakDetector<T> extends ResourceLeakDetector<T> {
    private static final VarHandle ALL_LEAKS_FIELD;

    static {
        try {
            ALL_LEAKS_FIELD = MethodHandles.privateLookupIn(ResourceLeakDetector.class, MethodHandles.lookup())
                    .findVarHandle(ResourceLeakDetector.class, "allLeaks", Set.class);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    private static final List<Leak> LEAKS = new CopyOnWriteArrayList<>();
    private static final List<ResourceLeakDetector<?>> DETECTORS = new CopyOnWriteArrayList<>();

    private static volatile ResourceLeakHint currentHint = new FixedHint(null);

    public CustomResourceLeakDetector(Class<?> resourceType, int samplingInterval) {
        super(resourceType, samplingInterval);
        DETECTORS.add(this);
    }

    static void register() {
        ResourceLeakDetector.setLevel(Level.PARANOID);
        ResourceLeakDetectorFactory.setResourceLeakDetectorFactory(new ResourceLeakDetectorFactory() {
            @Override
            public <T> ResourceLeakDetector<T> newResourceLeakDetector(Class<T> resource, int samplingInterval, long maxActive) {
                // maxActive is ignored by netty anyway, that constructor is deprecated
                return new CustomResourceLeakDetector<>(resource, samplingInterval);
            }
        });
    }

    public static void setCurrentInput(byte[] input) {
        currentHint = new FixedHint(input);
    }

    @Override
    protected boolean needReport() {
        return true;
    }

    @Override
    protected void reportTracedLeak(String resourceType, String records) {
        LEAKS.add(new Leak(resourceType, records));
        super.reportTracedLeak(resourceType, records);
    }

    @Override
    protected void reportUntracedLeak(String resourceType) {
        LEAKS.add(new Leak(resourceType, null));
        super.reportUntracedLeak(resourceType);
    }

    @Override
    protected Object getInitialHint(String resourceType) {
        return currentHint;
    }

    static void reportLeaks() {
        if (!LEAKS.isEmpty()) {
            StringBuilder msg = new StringBuilder("Reported leaks! Probably unrelated to this particular run, though.\n");
            for (Leak leak : LEAKS) {
                msg.append(leak.resourceType).append("\n");
                msg.append(leak.records).append("\n");
            }
            throw new RuntimeException(msg.toString());
        }
    }

    static void reportStillOpen() {
        Logger logger = LoggerFactory.getLogger(CustomResourceLeakDetector.class);
        String found = null;
        for (ResourceLeakDetector<?> detector : DETECTORS) {
            Set<?> s = (Set<?>) ALL_LEAKS_FIELD.get(detector);
            for (Object o : s) {
                String v = o.toString();
                if (v.contains("<clinit>")) {
                    logger.debug("Skipping still-open resource that has a <clinit> stack, so is probably irrelevant.");
                } else {
                    logger.info("Still open: {}", v);
                    found = v;
                }
            }
        }
        if (found != null) {
            throw new RuntimeException("Still open: " + found);
        }
    }

    private record Leak(String resourceType, String records) {
    }

    private static final class FixedHint implements ResourceLeakHint {
        private final String msg;

        private FixedHint(byte[] associatedInput) {
            this.msg = "Associated input: " + (associatedInput == null ? "<none>" : Base64.getEncoder().encodeToString(associatedInput));
        }

        @Override
        public String toHintString() {
            return msg;
        }
    }
}

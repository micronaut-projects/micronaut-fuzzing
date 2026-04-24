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
package io.micronaut.fuzzing.sanitizer;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import com.code_intelligence.jazzer.api.Jazzer;
import io.micronaut.core.annotation.Internal;

/**
 * Reports sanitizer findings.
 */
@Internal
final class FindingReporter {
    private static volatile Reporter reporter = FindingReporter::reportViaJazzer;

    private FindingReporter() {
    }

    static void reportCritical(String message) {
        reporter.report(message);
    }

    static Reporter replaceForTesting(Reporter replacement) {
        Reporter previous = reporter;
        reporter = replacement;
        return previous;
    }

    private static void reportViaJazzer(String message) {
        Jazzer.reportFindingFromHook(new FuzzerSecurityIssueCritical(message));
    }

    @FunctionalInterface
    interface Reporter {
        void report(String message);
    }
}

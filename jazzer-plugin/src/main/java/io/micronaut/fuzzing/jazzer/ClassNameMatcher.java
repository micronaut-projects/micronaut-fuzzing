package io.micronaut.fuzzing.jazzer;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

final class ClassNameMatcher {
    private final Set<String> exactMatch;
    private final List<String> prefixes;

    public ClassNameMatcher(Collection<String> patterns) {
        exactMatch = new HashSet<>();
        prefixes = new ArrayList<>();
        for (String pattern : patterns) {
            if (pattern.endsWith("*")) {
                prefixes.add(pattern.substring(0, pattern.length() - 1));
            } else {
                exactMatch.add(pattern);
            }
        }
    }

    public boolean matches(String className) {
        return exactMatch.contains(className) || prefixes.stream().anyMatch(className::startsWith);
    }

    public boolean isEmpty() {
        return exactMatch.isEmpty() && prefixes.isEmpty();
    }
}

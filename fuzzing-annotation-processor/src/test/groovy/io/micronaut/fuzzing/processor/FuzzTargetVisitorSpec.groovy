package io.micronaut.fuzzing.processor

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import io.micronaut.annotation.processing.test.AbstractTypeElementSpec

class FuzzTargetVisitorSpec extends AbstractTypeElementSpec {
    def 'simple'() {
        given:
        def mapper = new ObjectMapper()

        when:
        def cl = buildClassLoader("com.example.Example", """
package com.example;

import io.micronaut.fuzzing.FuzzTarget;

@FuzzTarget
class Example {
    static void fuzzerTestOneInput(byte[] input) {
    }
}
""")
        def value = mapper.readValue(cl.getResources("META-INF/" + DefinedFuzzTarget.DIRECTORY).nextElement(), new TypeReference<List<DefinedFuzzTarget>>() {
        })
        then:
        value == [new DefinedFuzzTarget("com.example.Example", null, null)]
    }

    def 'static dict'() {
        given:
        def mapper = new ObjectMapper()

        when:
        def cl = buildClassLoader("com.example.Example", """
package com.example;

import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.FuzzTarget;

@FuzzTarget
@Dict("foo")
class Example {
    static void fuzzerTestOneInput(byte[] input) {
    }
}
""")
        def value = mapper.readValue(cl.getResources("META-INF/" + DefinedFuzzTarget.DIRECTORY).nextElement(), new TypeReference<List<DefinedFuzzTarget>>() {
        })
        then:
        value.size() == 1
        when:
        def single = value.get(0)
        then:
        single.dictionary().contains("foo")
    }
}

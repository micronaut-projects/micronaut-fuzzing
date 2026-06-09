package io.micronaut.fuzzing.processor

import tools.jackson.databind.ObjectMapper
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
        def value = cl.getResources("META-INF/" + DefinedFuzzTarget.DIRECTORY).nextElement().openStream().withCloseable { stream ->
            mapper.readValue(stream, DefinedFuzzTarget[])
        }
        then:
        value.size() == 1
        value[0].targetClass() == "com.example.Example"
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
        def value = cl.getResources("META-INF/" + DefinedFuzzTarget.DIRECTORY).nextElement().openStream().withCloseable { stream ->
            mapper.readValue(stream, DefinedFuzzTarget[])
        }
        then:
        value.size() == 1
        when:
        def single = value[0]
        then:
        single.dictionary().contains("foo")
    }
}

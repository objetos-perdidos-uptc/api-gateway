package co.darpidev.apigatewaylostobjects.security;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class BearerTokenExtractorTest {

    @Test
    void extractsTokenFromBearerHeader() {
        assertThat(BearerTokenExtractor.extract("Bearer abc.def.ghi").getValue()).isEqualTo("abc.def.ghi");
    }

    @Test
    void failsWhenHeaderIsMissing() {
        assertThat(BearerTokenExtractor.extract(null).getError()).isEqualTo(AuthErrors.missingToken());
    }

    @Test
    void failsWhenSchemeIsNotBearer() {
        assertThat(BearerTokenExtractor.extract("Basic dXNlcjpwYXNz").getError()).isEqualTo(AuthErrors.missingToken());
    }

    @Test
    void failsWhenTokenIsEmpty() {
        assertThat(BearerTokenExtractor.extract("Bearer   ").getError()).isEqualTo(AuthErrors.missingToken());
    }
}

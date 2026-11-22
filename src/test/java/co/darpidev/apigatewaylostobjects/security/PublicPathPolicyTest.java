package co.darpidev.apigatewaylostobjects.security;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PublicPathPolicyTest {

    private final PublicPathPolicy policy =
            new PublicPathPolicy(new GatewaySecurityProperties(List.of("/auth/login", "/auth/register")));

    @Test
    void configuredPathsArePublic() {
        assertThat(policy.isPublic("/auth/login")).isTrue();
        assertThat(policy.isPublic("/auth/register")).isTrue();
        assertThat(policy.isPublic("/auth/login/")).isTrue();
    }

    @Test
    void everythingElseRequiresAuthentication() {
        assertThat(policy.isPublic("/claims/1")).isFalse();
        assertThat(policy.isPublic("/auth/other")).isFalse();
        assertThat(policy.isPublic("/")).isFalse();
    }

    @Test
    void emptyConfigurationMakesNothingPublic() {
        assertThat(new PublicPathPolicy(new GatewaySecurityProperties(null)).isPublic("/auth/login")).isFalse();
    }
}

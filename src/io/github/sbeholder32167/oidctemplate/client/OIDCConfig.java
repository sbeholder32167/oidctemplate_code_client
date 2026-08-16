/*
 Copyright 2026 sbeholder6684@gmail.com

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and limitations under the License.
 */
package io.github.sbeholder32167.oidctemplate.client;

import org.springframework.stereotype.Component;

import java.util.Objects;

/**
 * OIDC Config Class.
 *
 * <p>OIDC 인증 관련 각종 Parameter 및 URI 정보를 가지는 Value Object Class.<br>
 * </p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-22
 */
@Component(value="OIDCConfig")
public class OIDCConfig {
    private String clientId;
    private String clientSecret;
    private String authenticationEndpoint;
    private String tokenEndpoint;
    private String jwksUri;
    private String scope;
    private String redirectUri;
    private String authzEndpoint;
    private String logoutUri;
    private String postLogoutUri;
    private String usePkce = "Y";
    //-- GOOGLE, KAKAO ...
    private String provider = "KEYCLOAK";

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

    public String getTokenEndpoint() { return tokenEndpoint; }
    public void setTokenEndpoint(String tokenEndpoint) { this.tokenEndpoint = tokenEndpoint; }

    public String getAuthenticationEndpoint() { return authenticationEndpoint; }
    public void setAuthenticationEndpoint(String authenticationEndpoint) { this.authenticationEndpoint = authenticationEndpoint; }

    public String getJwksUri() { return jwksUri; }
    public void setJwksUri(String jwksUri) { this.jwksUri = jwksUri; }

    public String getScope() {
        return scope;
    }
    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getRedirectUri() {
        return redirectUri;
    }
    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public boolean isUsePkce(){
        return Objects.equals(this.usePkce.toUpperCase(), "Y");
    }
    public void setUsePkce(final String usePkce){
        this.usePkce = usePkce;
    }

    public String getProvider() {
        return provider;
    }
    public void setProvider(String provider) {
        this.provider = provider;
    }

    public String getAuthzEndpoint() {
        if (this.provider.equalsIgnoreCase("KEYCLOAK")) return this.tokenEndpoint;
        return authzEndpoint;
    }
    public void setAuthzEndpoint(String authzEndpoint) {
        this.authzEndpoint = authzEndpoint;
    }

    public String getLogoutUri() {
        return logoutUri;
    }
    public void setLogoutUri(String logoutUri) {
        this.logoutUri = logoutUri;
    }

    public String getPostLogoutUri() {
        return postLogoutUri;
    }
    public void setPostLogoutUri(String postLogoutUri) {
        this.postLogoutUri = postLogoutUri;
    }
}
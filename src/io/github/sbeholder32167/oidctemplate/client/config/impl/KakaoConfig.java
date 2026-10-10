package io.github.sbeholder32167.oidctemplate.client.config.impl;

import io.github.sbeholder32167.oidctemplate.client.config.OIDCConfig;
import io.github.sbeholder32167.oidctemplate.client.exception.ConfigException;
import io.github.sbeholder32167.oidctemplate.rest.RestfulUtil;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import javax.annotation.PostConstruct;

public class KakaoConfig extends OIDCConfig {
    private final RestfulUtil restfulUtil;
    public KakaoConfig(RestfulUtil restfulUtil){
        this.restfulUtil = restfulUtil;
        //-- Discovery URL에 없으므로 수동으로 추가함.
        this.logoutUri = "https://kauth.kakao.com/oauth/logout";
    }

    @PostConstruct
    private void initialize() throws ConfigException {
        final String googleDiscoveryUrl = "https://kauth.kakao.com/.well-known/openid-configuration";
        ResponseEntity<OIDCConfig> response = this.restfulUtil.doRestful(googleDiscoveryUrl, HttpMethod.GET, new HttpHeaders(), null, OIDCConfig.class);
        if (response == null || response.getStatusCode().value() != 200){
            throw new ConfigException("Failed to load Kakao configuration.");
        }
        this.issuer = response.getBody().getIssuer();
        this.authenticationEndpoint = response.getBody().getAuthenticationEndpoint();
        this.tokenEndpoint = response.getBody().getTokenEndpoint();
        this.jwksUri = response.getBody().getJwksUri();
        this.userinfoEndpoint = response.getBody().getUserinfoEndpoint();
    }
}

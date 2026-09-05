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
package io.github.sbeholder32167.oidctemplate.client.config.impl;

import io.github.sbeholder32167.oidctemplate.client.config.OIDCConfig;
import io.github.sbeholder32167.oidctemplate.client.exception.RBACException;
import io.github.sbeholder32167.oidctemplate.rest.RestfulUtil;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import javax.annotation.PostConstruct;

/**
 * Naver Config Class.
 *
 * <p>Naver Social Login 관련 Endpoint Config.<br>
 * Discovery URL 사용
 * </p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-09-03
 */
public class NaverConfig extends OIDCConfig {
    private final RestfulUtil restfulUtil;
    public NaverConfig(final RestfulUtil restfulUtil){
        this.restfulUtil = restfulUtil;
        //-- Discovery URL에 없으므로 수동으로 추가함.
        this.revokeEndpoint = "https://nid.naver.com/oauth2.0/revoke";
    }

    @PostConstruct
    private void initialize() throws RBACException {
        final String googleDiscoveryUrl = "https://nid.naver.com/.well-known/openid-configuration";
        ResponseEntity<OIDCConfig> response = this.restfulUtil.doRestful(googleDiscoveryUrl, HttpMethod.GET, new HttpHeaders(), null, OIDCConfig.class);
        if (response == null || response.getStatusCode().value() != 200){
            throw new RBACException("Failed to load Naver configuration.");
        }
        this.issuer = response.getBody().getIssuer();
        this.authenticationEndpoint = response.getBody().getAuthenticationEndpoint();
        this.tokenEndpoint = response.getBody().getTokenEndpoint();
        this.jwksUri = response.getBody().getJwksUri();
        this.userinfoEndpoint = response.getBody().getUserinfoEndpoint();
    }
}

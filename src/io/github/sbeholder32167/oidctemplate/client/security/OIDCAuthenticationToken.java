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
package io.github.sbeholder32167.oidctemplate.client.security;

import io.github.sbeholder32167.oidctemplate.client.OIDCDataTransferObject;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.io.Serializable;

/**
 * OIDC 인증 Provider 진입용 Token.<br>
 *
 * <p>Spring Security 인증 토큰을 사용하는 OIDC 인증 객체<br>
 * OIDC Authentication provider를 이용하게 만드는 것 외에는 용도가 없음.<br>
 * 필드 추가 또는 커스터마이징 필요시 상속하여 사용<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-06-28
 */
public class OIDCAuthenticationToken extends AbstractAuthenticationToken{
    private final Serializable principal;
    //-- Token 보관
    private final Serializable credentials;
    /**
     * 인증되지 않은 인증 객체 생성<br>No Permission.(Not Authenticated.)
     * @param principal 식별자. 주로 ID
     * @param credentials 자격 증명. 여기서는 인증 파라미터 객체를 의미 {@link OIDCDataTransferObject}
     */
    public OIDCAuthenticationToken(Serializable principal, Serializable credentials) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
        setAuthenticated(false);
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }
    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof OIDCAuthenticationToken)) {
            return false;
        }
        OIDCAuthenticationToken nToken = (OIDCAuthenticationToken)obj;
        return this.principal == nToken.getPrincipal() && this.credentials == nToken.getCredentials();
    }
    @Override
    public int hashCode() {
        return super.hashCode();
    }
}

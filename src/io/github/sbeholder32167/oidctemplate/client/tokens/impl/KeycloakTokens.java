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
package io.github.sbeholder32167.oidctemplate.client.tokens.impl;

import com.auth0.jwt.interfaces.Claim;
import io.github.sbeholder32167.oidctemplate.client.OIDCTokenTransferObject;
import io.github.sbeholder32167.oidctemplate.client.exception.RBACException;
import io.github.sbeholder32167.oidctemplate.client.tokens.OIDCTokens;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import io.github.sbeholder32167.oidctemplate.util.OIDCUtil;

import java.util.Map;

/**
 * Keycloak Token 전용 Class.<br>
 *
 * <p>Keycloak 연동 시 사용되는 토큰 객체.<br>
 * IDP로부터 받은 Token Transfer Object를 저장하고 OIDC Session에 저장되는 클래스<br>
 * 토큰들로부터 추가적인 정보를 추출하여 세션에서 사용하고 싶다면 필요에 따라 상속하여 사용한다.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-06-28
 */
public class KeycloakTokens extends OIDCTokens {

    public KeycloakTokens(OIDCTokenTransferObject tto) throws RBACException {
        super(tto);
    }

    @Override
    protected void parseSidIdentifier() throws RBACException {
        //-- Extract SID from ID Token.
        Map<String, Claim> idTokenClaims = OIDCUtil.parseJwtPayload(this.tto.getIdToken());
        if (idTokenClaims == null || idTokenClaims.get("sid") == null ||
                idTokenClaims.get("sid").asString() == null || idTokenClaims.get("sid").asString().isEmpty()){
            LogUtil.error("OIDC Session Id is null.",this);
            throw new RBACException("OIDC Session Id is null.");
        }
        this.sid = idTokenClaims.get("sid").asString();
        if (idTokenClaims.get("preferred_username") == null){
            throw new RBACException("User Id is null.");
        }
        this.identifier = idTokenClaims.get("preferred_username").asString();
    }

    @Override
    public Object getDuplicateCheckKey() {
        //-- 비지니스 로직에 따라 각기 다를 수 있다.
        return this.identifier;
    }
}

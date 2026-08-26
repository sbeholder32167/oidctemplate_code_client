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
 * Google Token 전용 Class.<br>
 *
 * <p>Google 연동 시 사용되는 토큰 객체.<br>
 * IDP로부터 받은 Token Transfer Object를 저장하고 OIDC Session에 저장되는 클래스<br>
 * 토큰들로부터 추가적인 정보를 추출하여 세션에서 사용하고 싶다면 필요에 따라 상속하여 사용한다.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-06-28
 */
public class GoogleTokens extends OIDCTokens {
    private String sub;
    private String email;
    public GoogleTokens(OIDCTokenTransferObject tto) throws RBACException {
        super(tto);
    }

    @Override
    protected void parseSidIdentifier() throws RBACException {
        //-- Extract SUB from ID Token.
        Map<String, Claim> idTokenClaims = OIDCUtil.parseJwtPayload(this.tto.getIdToken());
        if (idTokenClaims == null || idTokenClaims.get("sub") == null ||
                idTokenClaims.get("sub").asString() == null || idTokenClaims.get("sub").asString().isEmpty()){
            LogUtil.error("Subject claim is null.",this);
            throw new RBACException("Subject claim is null.");
        }
        this.sub = idTokenClaims.get("sub").asString();
        //-- Keycloak처럼 SID를 Logout에 사용하지는 않으나, OIDC Session에서 ID로 사용되므로, 임의 생성 값 적용
        this.sid = OIDCUtil.generateState(32);
        if (idTokenClaims.get("email") == null){
            throw new RBACException("Email is null.");
        }
        this.email = idTokenClaims.get("email").asString();
        //-- sub를 사용할수도 있다.
        this.identifier = this.email.split("@")[0];
    }

    @Override
    public Object getDuplicateCheckKey() {
        return this.identifier;
    }

    public String getSub(){
        return this.sub;
    }
    public String getEmail(){
        return this.email;
    }
}

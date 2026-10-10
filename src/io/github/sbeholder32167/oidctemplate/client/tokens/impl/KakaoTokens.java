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
import io.github.sbeholder32167.oidctemplate.client.exception.TokenProcessingException;
import io.github.sbeholder32167.oidctemplate.client.tokens.OIDCTokens;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import io.github.sbeholder32167.oidctemplate.util.OIDCUtil;

import java.util.Map;

/**
 * Kakao Token 전용 Class.<br>
 *
 * <p>Kakao 연동 시 사용되는 토큰 객체.<br>
 * IDP로부터 받은 Token Transfer Object를 저장하고 OIDC Session에 저장되는 클래스<br>
 * 토큰들로부터 추가적인 정보를 추출하여 세션에서 사용하고 싶다면 필요에 따라 상속하여 사용한다.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-10-07
 */
public class KakaoTokens extends OIDCTokens {
    public KakaoTokens(OIDCTokenTransferObject tto) throws TokenProcessingException {
        super(tto);
    }

    @Override
    protected void parseSidIdentifier() throws TokenProcessingException {
        //-- Extract SUB from ID Token.
        Map<String, Claim> idTokenClaims = OIDCUtil.parseJwtPayload(this.tto.getIdToken());
        if (idTokenClaims == null || idTokenClaims.get("sub") == null ||
                idTokenClaims.get("sub").asString() == null || idTokenClaims.get("sub").asString().isEmpty()){
            LogUtil.error("Subject claim is null.",this);
            throw new TokenProcessingException("Subject claim is null.");
        }
        //-- Keycloak처럼 SID를 Logout에 사용하지는 않으나, OIDC Session에서 ID로 사용되므로, 임의 생성 값 적용
        this.sid = OIDCUtil.generateState(32);
        //-- Kakao email 정보수집은 쉽게 허가해주지 않으므로, 고유 식별자로는 회원번호인 sub를 사용
        this.identifier = idTokenClaims.get("sub").asString();
    }

    @Override
    public Object getDuplicateCheckKey() {
        return this.identifier;
    }
}
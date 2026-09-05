package io.github.sbeholder32167.oidctemplate.client.tokens.impl;

import com.auth0.jwt.interfaces.Claim;
import io.github.sbeholder32167.oidctemplate.client.OIDCTokenTransferObject;
import io.github.sbeholder32167.oidctemplate.client.exception.RBACException;
import io.github.sbeholder32167.oidctemplate.client.tokens.OIDCTokens;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import io.github.sbeholder32167.oidctemplate.util.OIDCUtil;

import java.util.Map;

public class NaverTokens extends OIDCTokens {
    public NaverTokens(OIDCTokenTransferObject tto) throws RBACException {
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
        //-- Keycloak처럼 SID를 Logout에 사용하지는 않으나, OIDC Session에서 ID로 사용되므로, 임의 생성 값 적용
        this.sid = OIDCUtil.generateState(32);
        //-- Naver의 email 정보는 언제나 사용자에 의해 변경될수 있으므로, 고유 식별자로 사용하기 부적절.
        this.identifier = idTokenClaims.get("sub").asString();
    }

    @Override
    public Object getDuplicateCheckKey() {
        return this.identifier;
    }
}
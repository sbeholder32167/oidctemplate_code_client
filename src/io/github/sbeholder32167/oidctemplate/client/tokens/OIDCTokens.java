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
package io.github.sbeholder32167.oidctemplate.client.tokens;

import io.github.sbeholder32167.oidctemplate.client.OIDCTokenTransferObject;
import io.github.sbeholder32167.oidctemplate.client.exception.RBACException;

import java.io.Serializable;

/**
 * OIDC Token 추상 Class<br>
 *
 * <p>OIDC Session에 포함되는 객체 (Security / Non-Security)<br>
 * 필요에 따라 상속하여 사용<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-06-28
 */
public abstract class OIDCTokens implements Serializable {
    protected final OIDCTokenTransferObject tto;
    protected String identifier;
    protected String sid;
    protected OIDCTokens(OIDCTokenTransferObject tto) throws RBACException {
        this.tto = tto;
        this.parseSidIdentifier();
    }

    /**
     * 내부 필드 Parsing.<br> SID와 식별자 (사용자 ID)를 파싱하여 멤버 Field로 넣을 것.<br>
     * 다른 추가적인 Field를 파싱할 때도 사용
     * @throws RBACException Token 값이 없을 경우 사용
     */
    protected abstract void parseSidIdentifier() throws RBACException;
    /**
     * 식별자를 가져온다<br>
     * 주로 User ID. Spring Security에서의 Principal.
     * @return 식별자
     */
    public String getIdentifier(){
        return this.identifier;
    }
    public String getSid(){
        return this.sid;
    }

    /**
     * 토큰 전달 객체를 가져온다<br>
     * OIDCTokenTransferObject<br> Spring Security에서의 Credential.
     * @return 토큰 전달 객체
     */
    public OIDCTokenTransferObject getTokenTransferObj(){
        return this.tto;
    }

    /**
     * Access Token을 가져온다
     * @return AccessToken Raw 문자열
     */
    public String getAccessToken(){
        return this.tto.getAccessToken();
    }

    /**
     * Access Token을 저장한다.<br> Refresh Mechanism에 따른 갱신 필요.
     * @param accessToken Access Token 문자열
     */
    public void setAccessToken(final String accessToken){
        this.tto.setAccessToken(accessToken);
    }

    /**
     * ID Token을 가져온다
     * @return IdToken Raw 문자열
     */
    public String getIDToken(){
        return this.tto.getIdToken();
    }

    /**
     * refresh Token을 가져온다
     * @return refreshToken Raw 문자열
     */
    public String getRefreshToken(){
        return this.tto.getRefreshToken();
    }

    /**
     * Refresh Token을 저장한다.<br> Revoke Refresh Mechanism에 따른 갱신.
     * @param refreshToken Refresh Token 문자열
     */
    public void setRefreshToken(final String refreshToken){
        this.tto.setRefreshToken(refreshToken);
    }

    /**
     * OIDC 세션 중복 체크를 위한 Key를 가져온다.<br>
     * 보통 principal의 식별자 또는 UserID를 사용한다.<br>
     * 사용을 하지 않는다면 null을 리턴하고, OIDC Session Registry 구현체에서 그것을 사용하지 않도록 구현하면 된다.
     * @return Session Duplicate 확인용 Key
     */
    public abstract Object getDuplicateCheckKey();
}

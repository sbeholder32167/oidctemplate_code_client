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

import java.io.Serializable;

/**
 * OIDC Token 전달 객체.<br>
 *
 * <p>OIDC 인증 후 Token 정보를 보유한다.<br>
 * OIDCTokens 객체 내 존재<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-27
 */
public class OIDCTokenTransferObject implements Serializable {
    private String idToken;
    private String accessToken;
    private String refreshToken;
    private int expiresIn;
    private int refreshExpiresIn;
    public String getIdToken() {
        return idToken;
    }
    public void setIdToken(String idToken) {
        this.idToken = idToken;
    }
    public String getAccessToken() {
        return accessToken;
    }
    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }
    public String getRefreshToken() {
        return refreshToken;
    }
    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
    public int getExpiresIn() {
        return expiresIn;
    }
    public void setExpiresIn(int expiresIn) {
        this.expiresIn = expiresIn;
    }
    public int getRefreshExpiresIn() {
        return refreshExpiresIn;
    }
    public void setRefreshExpiresIn(int refreshExpiresIn) {
        this.refreshExpiresIn = refreshExpiresIn;
    }
}

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
 * OIDC 인증 DTO.<br>
 *
 * OIDC 인증 전 Code Flow에서 사용되는 데이터 전달 객체.<br>
 * Authentication Filter -> Authentication Provider 전달 간 데이터 전달 객체<br>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-23
 */
public class OIDCDataTransferObject implements Serializable {
    private String code;
    private String state;
    private String sessionState;
    private String scope;
    private String codeVerifier;
    /**
     * Request Session Id
     */
    private String sessionId;
    public String getCode() {
        return code;
    }
    public void setCode(String code) {
        this.code = code;
    }
    public String getState() {
        return state;
    }
    public void setState(String state) {
        this.state = state;
    }
    public String getSessionState() {
        return sessionState;
    }
    public void setSessionState(String sessionState) {
        this.sessionState = sessionState;
    }
    public String getScope() {
        return scope;
    }
    public void setScope(String scope) {
        this.scope = scope;
    }
    public String getCodeVerifier() {
        return codeVerifier;
    }
    public void setCodeVerifier(String codeVerifier) {
        this.codeVerifier = codeVerifier;
    }
    public String getSessionId() {
        return sessionId;
    }
    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }
}

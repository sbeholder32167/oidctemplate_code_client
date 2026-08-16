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
package io.github.sbeholder32167.oidctemplate.client.nonsecurity;

import io.github.sbeholder32167.oidctemplate.OIDCConstants;
import io.github.sbeholder32167.oidctemplate.adapter.ClientLoginAdapter;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSession;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSessionManager;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import io.github.sbeholder32167.oidctemplate.util.OIDCUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * OIDC 인증 성공 시 사용되는 Handler Class.<br>
 *
 * <p>Spring Security가 없는 환경에서 사용할 것.<br>
 * Provider / Controller 모두 사용된다.<br>
 * Bean으로 등록되어 사용된다.<br>
 * 필요시 상속 후 재정의하여 사용할 것.</p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-23
 */
//-- XML에서 Bean으로 등록
public class OIDCAuthSuccessHandler {
    private final OIDCSessionManager oidcSessionManager;
    public OIDCAuthSuccessHandler(OIDCSessionManager oidcSessionManager){
        this.oidcSessionManager = oidcSessionManager;
    }

    private String loginSuccessUri = "/";
    public void setLoginSuccessUri(final String uri){
        this.loginSuccessUri = uri;
    }

    private ClientLoginAdapter clientLoginAdapter;
    public void setClientLoginAdapter(final ClientLoginAdapter clientLoginAdapter){
        this.clientLoginAdapter = clientLoginAdapter;
    }

    /**
     * OIDC 인증이 성공했을 경우 동작하는 Handler<br>
     * OIDC 세션 등록을 여기서 진행한다.<br>
     * IDP로부터 SID를 받지 못했거나, Session이 중복되었을 경우 실패 동작으로 진행.<br>
     * 필요한 경우 상속하고 재정의하여 사용할 것.<br>
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @param legacySessionObj Legacy Session 인증 객체. Auth Convert Adapter에서 작성된 구현체.
     * @throws IOException 실패 동작 중 Redirect 실패 시
     */
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Object legacySessionObj) throws IOException {
        //-- Business Logic을 위한 확장 인터페이스
        if (this.clientLoginAdapter != null) {
            String sessionId = OIDCUtil.getCookieValue(request, OIDCConstants.COOKIE_NAME);
            OIDCSession oidcSession = this.oidcSessionManager.getSessionBySessionID(sessionId);
            if (oidcSession != null){
                this.clientLoginAdapter.doJobPostLogin(request, response, oidcSession.getTokens(), legacySessionObj);
            }else{
                LogUtil.error("OIDC Session is null.", this);
                response.sendRedirect(request.getContextPath() + this.loginSuccessUri);
            }
        }else{
            response.sendRedirect(request.getContextPath() + this.loginSuccessUri);
        }
    }
}

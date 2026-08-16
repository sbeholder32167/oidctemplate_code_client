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
package io.github.sbeholder32167.oidctemplate.client.session;

import io.github.sbeholder32167.oidctemplate.OIDCConstants;
import io.github.sbeholder32167.oidctemplate.client.session.storage.OIDCAuthParameterStorage;
import io.github.sbeholder32167.oidctemplate.exception.OIDCException;
import io.github.sbeholder32167.oidctemplate.exception.OIDCExceptionEnum;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import io.github.sbeholder32167.oidctemplate.util.OIDCUtil;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * OIDC Session Interceptor.<br>
 *
 * <p>OIDC Session이 존재할 경우 세션 Timeout을 연장시켜주며, <br>
 * OIDC Session이 삭제되거나 만료될 경우 WAS Session의 상태를 무효처리 해준다.<br>
 * 명시적인 수동 IDP Logout 및 IDP에서의 FrontChannel / BackChannel Logout 처리에 따른 Lazy Invalidate 동작도 담당.<br>
 * OIDC Filter로 기능을 합치려 했으나, SRP를 고려하여 따로 작성함.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-06-21
 */
//-- XML Bean 등록 또는 Configuration 수동 등록
public class OIDCSessionInterceptor implements HandlerInterceptor {
    private final OIDCSessionManager oidcSessionManager;
    private final OIDCAuthParameterStorage requestParameterStorage;

    public OIDCSessionInterceptor(OIDCSessionManager oidcSessionManager,
                                  OIDCAuthParameterStorage requestParameterStorage){
        this.oidcSessionManager = oidcSessionManager;
        this.requestParameterStorage = requestParameterStorage;
    }

    private String mainPageUri = "/";
    /**
     * 메인 페이지 또는 세션 없이 보여지는 최초 화면의 URI를 지정한다<br>
     * Legacy 세션이 없어도 OIDC Session 만료 확인 동작은 보장하기 위함<br>
     * @param mainPageUri 메인 페이지 URI
     */
    public void setMainPageUri(final String mainPageUri){
        this.mainPageUri = mainPageUri;
    }

    //-- 세션이 만료된 후 요청 시 이동할 화면의 Uri
    private String exceptionUri = "/";
    /**
     * 세션이 만료된 후 요청 시 이동할 화면의 Uri를 설정한다<br>
     * @param exceptionUri 세션이 만료된 후 Uri
     */
    public void setExceptionUri(final String exceptionUri){
        this.exceptionUri = exceptionUri;
    }

    private void clearWASSession(HttpServletRequest request){
        HttpSession session = request.getSession(false);
        if (session != null){
            session.invalidate();
        }
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // NOSONAR LogUtil.info("Incoming:" + request.getRequestURI(), this);
        // String sessionId = OIDCUtil.extractSessionId(request);
        //-- 다중 서버 운영 환경에서는 다른 서버에서 인증된 공유된 쿠키값이 유입되지만, 이 서버 인스턴스에서는 인증되지 않앗을 수 있다.
        String sessionId = OIDCUtil.getCookieValue(request, OIDCConstants.COOKIE_NAME);
        OIDCSession sObj = this.oidcSessionManager.getSessionBySessionID(sessionId);
        if (sObj != null){
            if (sObj.isExpired()){
                LogUtil.info("Session Invalidate:" + sessionId, this);
                //-- remove OIDC Session.
                this.oidcSessionManager.expireSession(request, response, sObj.getSid(),true);
                //-- Invalidate WAS session.
                this.clearWASSession(request);
                response.sendRedirect(request.getContextPath() + this.exceptionUri);
                return false;
            }else{
                // NOSONAR LogUtil.info("Session Extended:" + sessionAdapter.getSessionId(), this);
                try {
                    this.oidcSessionManager.maintainSession(sObj);
                }catch (OIDCException oe){
                    if (oe.getStep() == OIDCExceptionEnum.OIDC_SESSION_TIMED_OUT){
                        response.sendRedirect(request.getContextPath() + this.exceptionUri);
                        return false;
                    }
                }
                return true;
            }
        }else if (this.requestParameterStorage.getRequestParameterAdapter(sessionId) != null){
            HttpSession session = request.getSession(false);
            if (session != null) {
                LogUtil.info("session lived :" + session.getId(), this);
            }
            return true;
        }else{
            if (checkIfMainPage(request)){
                LogUtil.info("Main or Exception page. Ignored.", this);
                return true;
            }
            Object legacySessionObj = this.oidcSessionManager.getLegacySession(request, response);
            if (legacySessionObj != null){
                //-- Exist user for legacy Application.
                return true;
            }else{
                //-- clear WAS Session if Not in OIDC Session storage.
                //-- Invalidate WAS session.
                this.clearWASSession(request);
                response.sendRedirect(request.getContextPath() + this.exceptionUri);
                return false;
            }
        }
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView){
        //-- No needed to implement.
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex){
        //-- No needed to implement.
    }

    private boolean checkIfMainPage(HttpServletRequest request){
        final String requestURI = request.getRequestURI();
        return requestURI.contains(this.mainPageUri) || requestURI.contains(this.exceptionUri);
    }
}

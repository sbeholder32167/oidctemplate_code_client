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

import io.github.sbeholder32167.oidctemplate.adapter.ClientAuthConvertAdapter;
import io.github.sbeholder32167.oidctemplate.adapter.ClientLegacySessionAdapter;
import io.github.sbeholder32167.oidctemplate.exception.OIDCException;
import io.github.sbeholder32167.oidctemplate.exception.OIDCExceptionEnum;
import io.github.sbeholder32167.oidctemplate.exception.OIDCExceptionHandler;
import io.github.sbeholder32167.oidctemplate.client.OIDCDataTransferObject;
import io.github.sbeholder32167.oidctemplate.client.OIDCTokenTransferObject;
import io.github.sbeholder32167.oidctemplate.client.exception.RBACException;
import io.github.sbeholder32167.oidctemplate.client.provider.OIDCProvider;
import io.github.sbeholder32167.oidctemplate.client.tokens.OIDCTokens;
import io.github.sbeholder32167.oidctemplate.client.tokens.impl.KeycloakTokens;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSessionManager;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import io.github.sbeholder32167.oidctemplate.util.OIDCUtil;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * OIDC Login Filter.<br>
 *
 * <p>Spring Security가 없을 경우 사용되는 OIDC Login Filter 구현체<br>
 * OIDC Authentication Code Flow에 따른 동작을 여기서 진행한다.<br><br>
 * web.xml에 org.springframework.web.filter.DelegatingFilterProxy를 적용한 후<br>
 * Bean으로 등록하여 사용<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-07-12
 */
//-- XML Bean 등록
public class OIDCLoginFilter extends GenericFilterBean {
    private final String entryUri;
    private final String redirectUri;
    private final OIDCProvider oidcProvider;
    private final ClientAuthConvertAdapter authConvertAdapter;
    private final ClientLegacySessionAdapter clientLegacySessionAdapter;
    private final OIDCSessionManager oidcSessionManager;
    private OIDCExceptionHandler exceptionHandler;
    private final OIDCAuthSuccessHandler successHandler;
    private final OIDCAuthFailureHandler failureHandler;

    public OIDCLoginFilter(final String entryEndpoint, final String redirectEndpoint,
                           final OIDCProvider oidcProvider, final OIDCSessionManager oidcSessionManager,
                           final ClientAuthConvertAdapter authConvertAdapter,
                           final ClientLegacySessionAdapter clientLegacySessionAdapter,
                           final OIDCAuthSuccessHandler successHandler,
                           final OIDCAuthFailureHandler failureHandler){
        this.entryUri = entryEndpoint;
        this.redirectUri = redirectEndpoint;
        this.oidcProvider = oidcProvider;
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
        this.authConvertAdapter = authConvertAdapter;
        this.clientLegacySessionAdapter = clientLegacySessionAdapter;
        this.oidcSessionManager = oidcSessionManager;
    }
    public void setExceptionHandler(final OIDCExceptionHandler exceptionHandler){
        this.exceptionHandler = exceptionHandler;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        if (!requiresAuthentication(request)) {
            chain.doFilter(request, response);
            return;
        }
        OIDCAuthObj oidcAuthObj = this.attemptAuthentication(request, response);
        if (oidcAuthObj == null){
            OIDCException oe = new OIDCException(OIDCExceptionEnum.OIDC_SESSION_EXCEPTION, "Null OIDC Session.");
            LogUtil.error(oe.getLocalizedMessage(), this);
            if (this.exceptionHandler != null){
                this.exceptionHandler.handleException(oe.getStep(), oe, request, response);
            }
            return;
        }
        try {
            //-- OIDC Session register.
            String sessionId = OIDCUtil.extractSessionId(request);
            this.oidcSessionManager.registerOIDCSession(oidcAuthObj.getOidcTokens().getSid(), sessionId, oidcAuthObj.getOidcTokens());
        } catch (OIDCException e) {
            LogUtil.error(e.getLocalizedMessage(), this);
            if (this.exceptionHandler != null){
                this.exceptionHandler.handleException(e.getStep(), e, request, response);
            }
            this.failureHandler.onAuthenticationFailure(request,response, e);
            return;
        }

        //-- Legacy Session 처리
        this.clientLegacySessionAdapter.setSession(request, response, oidcAuthObj.getLegacySessionObj(), false, null);
        LogUtil.info("Legacy Session established.", this);
        try {
            this.successHandler.onAuthenticationSuccess(request, response, oidcAuthObj.getLegacySessionObj());
            LogUtil.info("Process OIDC Authentication finished.",this);
        } catch (IOException e) {
            //-- OIDC Login fail. 비지니스 로직에 맞게 구현 필요
            LogUtil.error(e.getMessage(), this);
        }
    }

    /**
     * 인증 시도
     * @param request 서블릿 요청 객체
     * @param response 서블릿 응답 객체
     * @return OIDC Token과 레거시 세션 객체를 담은 클래스.
     * @throws IOException OIDC 인증 페이지 Redirect 실패 시 발생
     */
    private OIDCAuthObj attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String requestURI = request.getRequestURI();
        //-- Entry Logic
        if (requestURI.contains(this.entryUri)) {
            try {
                this.oidcProvider.redirectIDPAuthPage(request, response, this.redirectUri);
            }catch(OIDCException oe){
                LogUtil.error(oe.getLocalizedMessage(), this);
                if (this.exceptionHandler != null){
                    this.exceptionHandler.handleException(oe.getStep(), oe, request, response);
                }
            }
            return null;
        }else if (requestURI.contains(this.redirectUri)) {
            //-- Redirect Logic..
            OIDCDataTransferObject dto;
            try {
                dto = this.oidcProvider.checkParameters(request);
            }catch(OIDCException oe){
                LogUtil.error(oe.getLocalizedMessage(), this);
                if (this.exceptionHandler != null){
                    this.exceptionHandler.handleException(oe.getStep(), oe, request, response);
                }
                return null;
            }
            //-- Session refresh section.(if required)
            //-- set Servlet request Session ID after refresh.
            String sessionId;
            try {
                sessionId = OIDCUtil.extractSessionId(request);
            } catch (OIDCException e) {
                LogUtil.error(e.getLocalizedMessage(), this);
                if (this.exceptionHandler != null){
                    this.exceptionHandler.handleException(e.getStep(), e, request, response);
                }
                return null;
            }
            dto.setSessionId(sessionId);
            OIDCTokenTransferObject tto;
            try {
                tto = this.oidcProvider.acquireTokens(dto, OIDCUtil.buildFullUrl(request, redirectUri));
            } catch (OIDCException e) {
                if (e.getStep() == OIDCExceptionEnum.NULL_TOKEN_RESPONSE){
                    LogUtil.error("No response from token endpoint.", this);
                }else if (e.getStep() == OIDCExceptionEnum.INSUFFICIENT_TOKEN){
                    LogUtil.error("Invalid token response from token endpoint.", this);
                }
                if (this.exceptionHandler != null){
                    this.exceptionHandler.handleException(e.getStep(), e, request, response);
                }
                return null;
            }
            if (tto == null){
                LogUtil.error("Null token response.", this);
                return null;
            }

            //-- Token verify process (JWKS, aud)
            try{
                this.oidcProvider.verifyToken(tto.getIdToken(), true);
                this.oidcProvider.verifyToken(tto.getAccessToken(), false);
            } catch (OIDCException e) {
                LogUtil.error("JWKS Error:" + e.getStep().name() + "-" + e.getMessage(), this);
                if (this.exceptionHandler != null){
                    this.exceptionHandler.handleException(e.getStep(), e, request, response);
                }
                return null;
            }
            LogUtil.info("Token verifying has been completed successfully.", this);

            try {
                OIDCTokens oidcTokens = new KeycloakTokens(tto);
                Object legacySessionObj = this.authConvertAdapter.buildAuthenticationUsingToken(tto);
                return new OIDCAuthObj(oidcTokens, legacySessionObj);
            } catch (RBACException e) {
                //-- OIDC Login fail. 비지니스 로직에 맞게 구현 필요
                LogUtil.error(e.getMessage(), this);
                if (this.exceptionHandler != null){
                    this.exceptionHandler.handleException(e.getStep(), e, request, response);
                }
                return null;
            }
        }else{
            LogUtil.error("Not Specified URI:" + requestURI, this);
            return null;
        }
    }

    /**
     * 인증 필요 여부 확인<br>Spring Security Source에서 이름만 참조
     * @param request 서블릿 요청 객체
     * @return Entry URI / Redirect URI만 true
     */
    private boolean requiresAuthentication(HttpServletRequest request) {
        final String requestURI = request.getRequestURI();
        return requestURI.contains(this.entryUri) || requestURI.contains(this.redirectUri);
    }

    static class OIDCAuthObj{
        private final OIDCTokens oidcTokens;
        private final Object legacySessionObj;
        OIDCAuthObj(OIDCTokens oidcTokens, Object legacySessionObj){
            this.oidcTokens = oidcTokens;
            this.legacySessionObj = legacySessionObj;
        }
        public OIDCTokens getOidcTokens() {
            return this.oidcTokens;
        }
        public Object getLegacySessionObj() {
            return this.legacySessionObj;
        }
    }
}
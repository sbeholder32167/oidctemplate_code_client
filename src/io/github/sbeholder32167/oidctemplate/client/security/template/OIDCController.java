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
package io.github.sbeholder32167.oidctemplate.client.security.template;

import io.github.sbeholder32167.oidctemplate.OIDCConstants;
import io.github.sbeholder32167.oidctemplate.adapter.ClientLogoutAdapter;
import io.github.sbeholder32167.oidctemplate.adapter.ClientAuthConvertAdapter;
import io.github.sbeholder32167.oidctemplate.client.security.OIDCAuthFailureHandler;
import io.github.sbeholder32167.oidctemplate.client.security.OIDCAuthSuccessHandler;
import io.github.sbeholder32167.oidctemplate.exception.OIDCException;
import io.github.sbeholder32167.oidctemplate.exception.OIDCExceptionEnum;
import io.github.sbeholder32167.oidctemplate.client.OIDCConfig;
import io.github.sbeholder32167.oidctemplate.client.OIDCDataTransferObject;
import io.github.sbeholder32167.oidctemplate.client.OIDCTokenTransferObject;
import io.github.sbeholder32167.oidctemplate.client.tokens.OIDCTokens;
import io.github.sbeholder32167.oidctemplate.client.tokens.impl.KeycloakTokens;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSession;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSessionManager;
import io.github.sbeholder32167.oidctemplate.client.OIDCEndpointsInterface;
import io.github.sbeholder32167.oidctemplate.util.OIDCUtil;
import io.github.sbeholder32167.oidctemplate.client.exception.RBACException;
import io.github.sbeholder32167.oidctemplate.client.provider.OIDCProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import javax.annotation.Resource;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * OIDC 인증 Logic Controller Class template. <br>
 *
 * <p>OIDC Controller 방식의 인증 사용시 사용되는 Controller Template Code.<br>
 * OIDC Login Filter / Logout Filter를 적용하기 어려운 환경에서 고려 대상이 될수 있다.<br>
 * 이 내용을 참조하여 새로운 Controller를 작성.<br>
 * 이용 시 반드시 Endpoint의 Path를 수정할 것.<br>
 * Spring Security 의존성이 필요하므로, Spring Security Package가 프로젝트 내에 있을 경우에만 동작.<br>
 * 복사하여 사용하는 Template Code.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-30
 */
//@Controller(value="oidcController")
public class OIDCController implements OIDCEndpointsInterface {
    private static final Logger log = LoggerFactory.getLogger(OIDCController.class);
    private static final String REDIRECT_URI = "/oidc_template_s/oidc_code.do";

    @Resource(name="OIDCConfig")
    private OIDCConfig config;
    @Resource(name="OIDCAuthSuccessHandler")
    private OIDCAuthSuccessHandler successHandler;
    @Autowired
    private OIDCAuthFailureHandler failureHandler;
    @Autowired
    private ClientLogoutAdapter logoutAdapter;
    @Autowired
    private ClientAuthConvertAdapter authConvertAdapter;
    @Autowired
    private OIDCProvider provider;
    @Autowired
    private OIDCSessionManager sessionManager;

    @Override
    @RequestMapping(path="/oidc_template_s/oidc.do",method = RequestMethod.GET)
    public void redirectOIDCAuthentication(HttpServletRequest request, HttpServletResponse response) throws IOException{
        try {
            this.provider.redirectIDPAuthPage(request, response, REDIRECT_URI);
        }catch(OIDCException oe){
            log.error("Exception:{}",oe.getLocalizedMessage());
            response.sendRedirect("/error=oidc_auth");
        }
    }

    @Override
    @RequestMapping(path=REDIRECT_URI, method=RequestMethod.GET)
    public void processOidcAuth(HttpServletRequest request, HttpServletResponse response) throws IOException{
        log.debug("Process OIDC Authentication start.");
        OIDCDataTransferObject dto = null;
        try {
            dto = this.provider.checkParameters(request);
        }catch(OIDCException oe){
            log.error(oe.getLocalizedMessage());
            if (oe.getStep() == OIDCExceptionEnum.CHECK_PARAMETERS){
                response.sendRedirect("/error=parameters");
                return;
            }else if (oe.getStep() == OIDCExceptionEnum.CHECK_STATE){
                response.sendRedirect("/error=state");
                return;
            }
        }
        if (dto == null){
            response.sendRedirect("/error=oidc");
            return;
        }

        log.debug("requesting tokens..");
        OIDCTokenTransferObject tto = null;
        try {
            tto = this.provider.acquireTokens(dto, OIDCUtil.buildFullUrl(request, REDIRECT_URI));
        } catch (OIDCException e) {
            if (e.getStep() == OIDCExceptionEnum.NULL_TOKEN_RESPONSE){
                log.error("No response from token endpoint.");
                response.sendRedirect("/error=no_token");
                return;
            }else if (e.getStep() == OIDCExceptionEnum.INSUFFICIENT_TOKEN){
                log.error("Invalid token response from token endpoint.");
                response.sendRedirect("/error=invalid_token");
                return;
            }
        }
        if (tto == null){
            log.error("Null token response.");
            response.sendRedirect("/error=no_token");
            return;
        }

        //-- Token verify process (JWKS, aud)
        try{
            this.provider.verifyToken(tto.getIdToken(), true);
            this.provider.verifyToken(tto.getAccessToken(), false);
        } catch (OIDCException e) {
            log.error("JWKS Error:{}-{}", e.getStep().name(), e.getMessage());
            response.sendRedirect("/error=verify_token");
            return;
        }
        log.debug("Token verifying has been completed successfully.");

        if (this.authConvertAdapter == null){
            log.error("Not injected Authentication Convert Adapter.");
            response.sendRedirect("/error=no_convert_adapter");
            return;
        }

        OIDCTokens oidcTokens;
        try {
            //-- OIDC Session register.
            String sessionId = OIDCUtil.extractSessionId(request);
            oidcTokens = new KeycloakTokens(tto);
            this.sessionManager.registerOIDCSession(oidcTokens.getSid(), sessionId, oidcTokens);
        } catch (OIDCException e) {
            log.error(e.getLocalizedMessage());
            if (this.failureHandler != null){
                try {
                    this.failureHandler.onAuthenticationFailure(request, response, new SessionAuthenticationException(e.getLocalizedMessage()));
                } catch (ServletException ex) {
                    log.error(ex.getLocalizedMessage());
                    response.sendRedirect("/error=session_register_exception");
                }
            }else{
                response.sendRedirect("/error=session_duplicate");
            }
            return;
        }

        Authentication authentication;
        try {
            authentication = (Authentication)this.authConvertAdapter.buildAuthenticationUsingToken(tto);
        } catch (RBACException e) {
            //-- OIDC Login fail. 비지니스 로직에 맞게 구현 필요
            response.sendRedirect("/error=build_token");
            return;
        }
        log.debug("Process OIDC Authentication finished.");

        //-- Client 세션 처리
        this.sessionManager.registerLegacySession(request, response, authentication);
        try {
            this.successHandler.onAuthenticationSuccess(request, response, authentication);
        } catch (IOException e) {
            //-- OIDC Login fail. 비지니스 로직에 맞게 구현 필요
            response.sendRedirect("/error=oidc_code");
        }
    }

    /**
     * Front Channel logout을 위한 Endpoint.<br>
     * 이 endpoint의 사용은 권장하지 않는다<br>
     * Edge에서 쿠키를 전달하지 않는 문제를 확인함.<br> 이로 인하여 사용자의 사용중 세션인지를 확인할 수가 없다.
     * Back Channel logout 사용 권장.
     * @param request 서블릿 요청 객체.
     * @param response 서블릿 응답 객체.
     * @param sid SID Claim 값
     * @param iss Issuer Claim 값
     */
    @Override
    @RequestMapping(path="/oidc_template_s/logout.do",method=RequestMethod.GET)
    public void handleFrontChannelLogout(HttpServletRequest request, HttpServletResponse response,
                                           @RequestParam("sid") String sid,
                                           @RequestParam(value = "iss", required = false) String iss) throws IOException {
        try {
            this.provider.doInboundIDPLogout(request, response, this.sessionManager, this.logoutAdapter);
        } catch (OIDCException e) {
            log.error(e.getLocalizedMessage());
        }
        response.sendRedirect(request.getContextPath() + this.config.getPostLogoutUri());
    }

    /**
     * Back Channel logout을 위한 Endpoint.<br>
     * 이 endpoint는 CSRF 보호를 하면 안된다.<br> IDP의 Logout 요청이 CSRF Token이 없이 여기로 진입된다.
     * @param request 서블릿 요청 객체.
     */
    @Override
    @RequestMapping(path="/oidc_template_s/logout.do",method=RequestMethod.POST)
    public void handleBackChannelLogout(HttpServletRequest request, HttpServletResponse response) throws IOException{
        try {
            this.provider.doInboundIDPLogout(request, response, this.sessionManager, this.logoutAdapter);
        } catch (OIDCException e) {
            log.error(e.getLocalizedMessage());
        }
        response.sendRedirect(request.getContextPath() + this.config.getPostLogoutUri());
    }

    /**
     * 사용자가 직접 로그아웃 할 경우 사용되는 엔드포인트<br>
     * @param request 서블릿 요청 객체
     * @param response 서블릿 응답 객체
     */
    @Override
    @RequestMapping("/oidc_template_s/manual_logout.do")
    public void doLogoutManually(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            this.provider.doOutboundIDPLogout(request, response, this.sessionManager, this.logoutAdapter);
        } catch (OIDCException | IOException e) {
            log.error(e.getLocalizedMessage());
        }
    }

    /**
     * Refresh Token 테스트 용 Endpoint.
     * @return 로그 확인.
     */
    @RequestMapping(path="/oidc_template_s/refresh_token.do",method=RequestMethod.GET)
    public String refreshTokenTest(HttpServletRequest req, HttpServletResponse res) {
        try {
            //-- Example : Refresh Token 테스트..
            String sessionId = OIDCUtil.getCookieValue(req, OIDCConstants.COOKIE_NAME);
            OIDCSession oidcSession = this.sessionManager.getSessionBySessionID(sessionId);
            String refreshToken = oidcSession.getTokens().getRefreshToken();
            log.debug("Refresh Token (Old):{}", refreshToken);
            OIDCTokenTransferObject tto = this.provider.refreshTokens(refreshToken);
            Authentication auth = (Authentication)this.sessionManager.getLegacySession(req, res);
            this.sessionManager.registerLegacySession(req, res, auth);
            log.info("ID Token:{}", tto.getIdToken());
            log.info("Access Token:{}", tto.getAccessToken());
            log.info("Refresh Token:{}", tto.getRefreshToken());
            log.info("Access Expires In:{}", tto.getExpiresIn());
            log.info("Refresh Expires In:{}", tto.getRefreshExpiresIn());
        } catch (OIDCException e) {
            log.error(e.getLocalizedMessage());
        }
        return "redirect:/";
    }
}
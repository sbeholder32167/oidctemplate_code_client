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
package io.github.sbeholder32167.oidctemplate.client.provider.impl;

import io.github.sbeholder32167.oidctemplate.OIDCConstants;
import io.github.sbeholder32167.oidctemplate.adapter.ClientLogoutAdapter;
import io.github.sbeholder32167.oidctemplate.client.OIDCDataTransferObject;
import io.github.sbeholder32167.oidctemplate.client.OIDCTokenTransferObject;
import io.github.sbeholder32167.oidctemplate.client.config.OIDCConfig;
import io.github.sbeholder32167.oidctemplate.client.exception.*;
import io.github.sbeholder32167.oidctemplate.client.provider.AbstractOIDCProvider;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSession;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSessionManager;
import io.github.sbeholder32167.oidctemplate.client.session.storage.OIDCAuthParameterStorage;
import io.github.sbeholder32167.oidctemplate.client.tokens.OIDCTokens;
import io.github.sbeholder32167.oidctemplate.client.tokens.impl.KakaoTokens;
import io.github.sbeholder32167.oidctemplate.verify.TokenVerifier;
import io.github.sbeholder32167.oidctemplate.verify.RSAJWKSVerifier;
import io.github.sbeholder32167.oidctemplate.rest.RestfulUtil;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import io.github.sbeholder32167.oidctemplate.util.OIDCUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.Map;
import java.util.UUID;

/**
 * Kakao 인증 제공자 Class.<br>
 *
 * <p>Kakao 인증에 필요한 동작 및 각종 Parameter와 Logic이 정의된 Class.<br>
 * Kakao 특성(토큰 구조, 파라미터명 등)이 반영되었다.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-10-07
 */
//-- XML Bean 등록
public class KakaoProvider extends AbstractOIDCProvider {
    public KakaoProvider(OIDCConfig config, RestfulUtil restfulUtil, OIDCAuthParameterStorage oidcAuthParameterStorage) {
        super(config, restfulUtil, oidcAuthParameterStorage);
    }

    @Override
    public void redirectIDPAuthPage(HttpServletRequest request, HttpServletResponse response, String redirectUri) throws AuthenticationCodeFlowException, IOException {
        String redirectUrl;
        if (redirectUri == null){
            redirectUrl = this.oidcConfig.getRedirectUri();
        }else{
            redirectUrl = OIDCUtil.buildFullUrl(request, redirectUri);
        }
        String sessionId;
        try {
            sessionId = OIDCUtil.extractSessionId(request);
        }catch(NoWasSessionException ne){
            throw new AuthenticationCodeFlowException(AuthenticationCodeFlowException.Step.IDP_AUTH_REDIRECT,
                    AuthenticationCodeFlowException.Cause.NULL_WAS_SESSION_ID,
                    ne.getMessage());
        }
        String state = OIDCUtil.generateState(16);
        this.oidcAuthParameterStorage.setRequestParameter(STATE_ATTR, state, sessionId);
        String nonce = UUID.randomUUID().toString();
        this.oidcAuthParameterStorage.setRequestParameter(NONCE_ATTR, nonce, sessionId);
        StringBuilder builder = new StringBuilder(this.oidcConfig.getAuthenticationEndpoint());
        builder.append("?client_id=").append(this.oidcConfig.getClientId())
                .append("&redirect_uri=").append(URLEncoder.encode(redirectUrl, "UTF-8"))
                .append("&response_type=code")
                .append("&scope=").append(this.oidcConfig.getScope())
                .append("&state=").append(state)
                .append("&nonce=").append(nonce);
        if (this.oidcConfig.isUsePkce()){
            String codeVerifier = OIDCUtil.generateCodeVerifier();
            this.oidcAuthParameterStorage.setRequestParameter(PKCE_ATTR, codeVerifier, sessionId);
            builder.append("&code_challenge=").append(OIDCUtil.generateCodeChallenge(codeVerifier))
                    .append("&code_challenge_method=S256");
        }
        String idpAuthUri = builder.toString();
        response.sendRedirect(idpAuthUri);
        // 현재 서블릿 응답을 완전히 플러시(Flush)하여 종료
        // 뒤쪽 스프링 필터 체인이나 컨트롤러가 동작하는 것을 완전히 차단
        response.getWriter().flush();
    }

    @Override
    public OIDCDataTransferObject checkParameters(HttpServletRequest request) throws AuthenticationCodeFlowException {
        String state = request.getParameter("state");
        String code = request.getParameter("code");
        String sessionId;
        try {
            sessionId = OIDCUtil.extractSessionId(request);
        }catch(NoWasSessionException ne){
            throw new AuthenticationCodeFlowException(AuthenticationCodeFlowException.Step.CHECK_PARAMETERS,
                    AuthenticationCodeFlowException.Cause.NULL_WAS_SESSION_ID,
                    ne.getMessage());
        }
        String savedState = String.valueOf(this.oidcAuthParameterStorage.getRequestParameterValue(STATE_ATTR, true, sessionId));
        String codeVerifier = String.valueOf(this.oidcAuthParameterStorage.getRequestParameterValue(PKCE_ATTR, true, sessionId));
        String nonce = String.valueOf(this.oidcAuthParameterStorage.getRequestParameterValue(NONCE_ATTR, true, sessionId));
        String scope = this.oidcConfig.getScope();
        if (state == null || state.isEmpty() ||
                code == null || code.isEmpty() ||
                savedState == null || savedState.isEmpty() ||
                scope == null || scope.isEmpty() ||
                codeVerifier == null || codeVerifier.isEmpty()){
            throw new AuthenticationCodeFlowException(AuthenticationCodeFlowException.Step.CHECK_PARAMETERS,
                    AuthenticationCodeFlowException.Cause.INSUFFICIENT,
                    "Not enough parameters.");
        }
        //-- Compare State in Session.
        if (!savedState.equals(state)) {
            throw new AuthenticationCodeFlowException(AuthenticationCodeFlowException.Step.CHECK_STATE,
                    AuthenticationCodeFlowException.Cause.INVALID,
                    "Invalid state.");
        }
        //-- Session clear.
        request.getSession().removeAttribute(STATE_ATTR);
        request.getSession().removeAttribute(PKCE_ATTR);
        this.oidcAuthParameterStorage.removeRequestParameterAdapter(sessionId);
        //-- Generate Result object.
        OIDCDataTransferObject result = new OIDCDataTransferObject();
        result.setState(state);
        result.setCode(code);
        result.setScope(scope);
        result.setCodeVerifier(codeVerifier);
        result.setSessionState("");
        result.setNonce(nonce);
        //-- 만약 보안을 위해 Session을 refresh할 경우, 여기서 session Id를 넣는 것은 무의미하다.
        // NOSONAR result.setSessionId(sessionId);
        return result;
    }

    @Override
    public OIDCTokenTransferObject acquireTokens(OIDCDataTransferObject dto, String redirectUri) throws AuthenticationCodeFlowException {
        Map<String, Object> tokenResponse = OIDCUtil.exchangeCodeForToken(
                this.restfulUtil, this.oidcConfig,
                dto.getCode(), dto.getCodeVerifier(), dto.getState(), "", dto.getScope(),
                redirectUri);
        if (tokenResponse == null || tokenResponse.isEmpty()){
            throw new AuthenticationCodeFlowException(AuthenticationCodeFlowException.Step.TOKEN_EXCHANGE,
                    AuthenticationCodeFlowException.Cause.NULL_VALUE, "Null Token response.");
        }
        if (!tokenResponse.containsKey(ACCESS_TOKEN)){
            throw new AuthenticationCodeFlowException(AuthenticationCodeFlowException.Step.TOKEN_EXCHANGE,
                    AuthenticationCodeFlowException.Cause.INSUFFICIENT, "Insufficient tokens");
        }
        OIDCTokenTransferObject result = new OIDCTokenTransferObject();
        if (tokenResponse.containsKey(ID_TOKEN) && !String.valueOf(tokenResponse.get(ID_TOKEN)).isEmpty()){
            result.setIdToken(String.valueOf(tokenResponse.get(ID_TOKEN)));
        }
        result.setAccessToken(String.valueOf(tokenResponse.get(ACCESS_TOKEN)));
        if (tokenResponse.containsKey(REFRESH_TOKEN)){
            result.setRefreshToken(String.valueOf(tokenResponse.get(REFRESH_TOKEN)));
        }

        if (tokenResponse.containsKey(EXPIRES_IN)){
            result.setExpiresIn(Integer.parseInt(String.valueOf(tokenResponse.get(EXPIRES_IN))));
        }
        //-- Kakao의 경우 Refresh Token 만료 시각 Claim 명이 다르다.
        if (tokenResponse.containsKey("refresh_token_expires_in")){
            result.setRefreshExpiresIn(Integer.parseInt(String.valueOf(tokenResponse.get("refresh_token_expires_in"))));
        }else{
            //-- 60 days as Kakao Refresh Token life span.
            result.setRefreshExpiresIn(86400 * 60);
        }
        return result;
    }

    @Override
    public OIDCTokenTransferObject refreshTokens(String refreshToken) throws TokenRefreshException {
        if (refreshToken == null || refreshToken.isEmpty()){
            LogUtil.info("Not available refresh token.", this);
            throw new TokenRefreshException(TokenRefreshException.Cause.INSUFFICIENT, "Not available refresh token.");
        }
        Map<String, Object> tokenResponse = OIDCUtil.refreshToken(this.restfulUtil, this.oidcConfig, refreshToken);
        if (tokenResponse == null || tokenResponse.isEmpty()){
            throw new TokenRefreshException(TokenRefreshException.Cause.NO_RESPONSE, "Null Token response.");
        }
        if (!tokenResponse.containsKey(ACCESS_TOKEN) || !tokenResponse.containsKey(EXPIRES_IN)){
            throw new TokenRefreshException(TokenRefreshException.Cause.INSUFFICIENT, "Insufficient tokens");
        }
        OIDCTokenTransferObject result = new OIDCTokenTransferObject();
        result.setAccessToken(String.valueOf(tokenResponse.get(ACCESS_TOKEN)));
        result.setExpiresIn(Integer.parseInt(String.valueOf(tokenResponse.get(EXPIRES_IN))));
        //-- not refreshing Refresh token.
        LogUtil.info("Old refresh token will be reused.", this);
        return result;
    }

    @Override
    public void verifyToken(OIDCTokenTransferObject tto, final String nonce) throws TokenVerifyException {
        TokenVerifier.verifyIDToken(tto.getIdToken(), this.oidcConfig, nonce);
        try{
            RSAJWKSVerifier.verifyToken(this.restfulUtil, this.oidcConfig.getJwksUri(), tto.getIdToken(), true);
        }catch(JWKSException je){
            throw new TokenVerifyException(TokenVerifyException.Cause.JWKS, "JWKS Error:" + je.step.name() + "-" +  je.getMessage());
        }
        this.queryTokenInfo(tto.getAccessToken());
    }

    @Override
    public OIDCTokens generateTokens(OIDCTokenTransferObject tto) throws TokenProcessingException {
        return new KakaoTokens(tto);
    }

    /**
     * Kakao의 IDP 동시 Logout 기능은 IDP가 먼저 Logout을 진행하고 그 후 Redirect되는 URI에서 Client Logout을 진행하는 것이 순서이다.<br/>
     * Keycloak의 경우와 다르므로 주의가 필요.<br/>
     *
     * @param request 서블릿 요청 객체
     * @param response 서블릿 응답 객체
     * @param oidcSessionManager OIDC 세션 관리자. 내부 OIDC Logout을 수행하기 위해 필요.
     * @param clientLogoutAdapter Client Logout Adapter. 내부 OIDC Logout 전/후 처리를 위해 필요.
     * @throws OIDCLogoutException OIDC 세션이 없을 경우 발생하는 예외
     * @throws IOException Redirect 중 발생하는 예외
     */
    @Override
    public void doOutboundIDPLogout(HttpServletRequest request, HttpServletResponse response,
                                    OIDCSessionManager oidcSessionManager, ClientLogoutAdapter clientLogoutAdapter) throws OIDCLogoutException, IOException{
        //-- Kakao의 경우 inboundLogoutUri를 KakaoConfig Bean에 반드시 설정해주어야 하며,
        //-- 그 값은 OIDCLogoutFilter의 idpLogoutUrl과 일치해야 한다
        //-- Redirect to Kakao Logout URI.
        String logoutUri = this.oidcConfig.getLogoutUri() + "?client_id=" + this.oidcConfig.getClientId() +
                "&logout_redirect_uri=" + this.oidcConfig.getInboundLogoutUri();
        response.sendRedirect(logoutUri);
    }

    @Override
    public void doInboundIDPLogout(HttpServletRequest request, HttpServletResponse response,
                                   OIDCSessionManager oidcSessionManager, ClientLogoutAdapter clientLogoutAdapter) throws OIDCLogoutException {
        //-- Kakao의 경우 Keycloak의 BackChannel Logout과 달리 Cookie가 유지되고 있다.
        String sessionId = OIDCUtil.getCookieValue(request, OIDCConstants.COOKIE_NAME);
        OIDCSession sObj = oidcSessionManager.getSessionBySessionID(sessionId);
        if (sObj == null) {
            throw new OIDCLogoutException(AuthenticationCodeFlowException.Cause.NO_OIDC_SESSION, "Not found session.");
        }
        //-- invalidate OIDC Session and legacy Session.
        OIDCUtil.doLogout(sObj.getSid(), request, response, oidcSessionManager,clientLogoutAdapter,true);
        try {
            response.sendRedirect(this.oidcConfig.getPostLogoutUri());
        } catch (IOException e) {
            LogUtil.error(e.getMessage(), this);
        }
    }
}

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

import com.auth0.jwt.interfaces.Claim;
import io.github.sbeholder32167.oidctemplate.OIDCConstants;
import io.github.sbeholder32167.oidctemplate.adapter.ClientLogoutAdapter;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSession;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSessionManager;
import io.github.sbeholder32167.oidctemplate.exception.OIDCException;
import io.github.sbeholder32167.oidctemplate.exception.OIDCExceptionEnum;
import io.github.sbeholder32167.oidctemplate.jwks.RSAJWKSVerifier;
import io.github.sbeholder32167.oidctemplate.jwks.exception.JWKSException;
import io.github.sbeholder32167.oidctemplate.client.*;
import io.github.sbeholder32167.oidctemplate.client.exception.RBACException;
import io.github.sbeholder32167.oidctemplate.client.provider.AbstractOIDCProvider;
import io.github.sbeholder32167.oidctemplate.rest.RestfulUtil;
import io.github.sbeholder32167.oidctemplate.client.session.storage.OIDCAuthParameterStorage;
import io.github.sbeholder32167.oidctemplate.util.KeycloakUtil;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import io.github.sbeholder32167.oidctemplate.util.OIDCUtil;
import org.springframework.http.HttpMethod;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.Map;

/**
 * Keycloak 인증 제공자 Class.<br>
 *
 * <p>Keycloak 인증에 필요한 동작 및 각종 Parameter와 Logic이 정의된 Class.<br>
 * Keycloak의 특성(토큰 구조, 파라미터명 등)이 반영되었다.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-06-28
 */
//-- XML Bean 등록
public class KeycloakProvider extends AbstractOIDCProvider {
    private static final String STATE_ATTR = "OIDC_STATE";
    private static final String PKCE_ATTR = "PKCE_VERIFIER";
    private static final String ID_TOKEN = "id_token";
    private static final String EXPIRES_IN = "expires_in";
    private static final String ACCESS_TOKEN = "access_token";
    private static final String REFRESH_EXPIRES_IN = "regresh_expires_in";
    private static final String REFRESH_TOKEN = "refresh_token";
    public KeycloakProvider(final OIDCConfig config, final RestfulUtil restfulUtil,
                            final OIDCAuthParameterStorage oidcAuthParameterStorage){
        super(config, restfulUtil, oidcAuthParameterStorage);
    }

    @Override
    public void redirectIDPAuthPage(HttpServletRequest request, HttpServletResponse response, final String redirectUri) throws OIDCException, IOException{
        String redirectUrl;
        if (redirectUri == null){
            redirectUrl = this.oidcConfig.getRedirectUri();
        }else{
            redirectUrl = OIDCUtil.buildFullUrl(request, redirectUri);
        }
        String sessionId = OIDCUtil.extractSessionId(request);
        String state = OIDCUtil.generateState();
        this.oidcAuthParameterStorage.setRequestParameter(STATE_ATTR, state, sessionId);
        StringBuilder builder = new StringBuilder(this.oidcConfig.getAuthenticationEndpoint());
        builder.append("?client_id=").append(this.oidcConfig.getClientId())
                .append("&redirect_uri=").append(URLEncoder.encode(redirectUrl, "UTF-8"))
                .append("&response_type=code")
                .append("&scope=").append(this.oidcConfig.getScope())
                .append("&state=").append(state);
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
    public OIDCDataTransferObject checkParameters(HttpServletRequest request) throws OIDCException {
        String state = request.getParameter("state");
        String code = request.getParameter("code");
        String sessionState = request.getParameter("session_state");
        String sessionId = OIDCUtil.extractSessionId(request);
        String savedState = String.valueOf(this.oidcAuthParameterStorage.getRequestParameterValue(STATE_ATTR, true, sessionId));
        String codeVerifier = String.valueOf(this.oidcAuthParameterStorage.getRequestParameterValue(PKCE_ATTR, true, sessionId));
        String scope = this.oidcConfig.getScope();
        if (state == null || state.isEmpty() ||
                code == null || code.isEmpty() ||
                savedState == null || savedState.isEmpty() ||
                scope == null || scope.isEmpty() ||
                codeVerifier == null || codeVerifier.isEmpty()){
            throw new OIDCException(OIDCExceptionEnum.CHECK_PARAMETERS, "Not enough parameters.");
        }
        //-- Compare State in Session.
        if (!savedState.equals(state)) {
            // NOSONAR throw new BadCredentialsException("Invalid OIDC State");
            throw new OIDCException(OIDCExceptionEnum.CHECK_STATE, "Invalid state.");
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
        result.setSessionState(sessionState);
        //-- 만약 보안을 위해 Session을 refresh할 경우, 여기서 session Id를 넣는 것은 무의미하다.
        // NOSONAR result.setSessionId(sessionId);
        return result;
    }

    public synchronized OIDCTokenTransferObject acquireTokens(OIDCDataTransferObject dto, final String redirectUri) throws OIDCException {
        Map<String, Object> tokenResponse = OIDCUtil.exchangeCodeForToken(
                this.restfulUtil, this.oidcConfig,
                dto.getCode(), dto.getCodeVerifier(), dto.getState(), dto.getSessionState(), dto.getScope(),
                redirectUri);
        if (tokenResponse == null || tokenResponse.isEmpty()){
            throw new OIDCException(OIDCExceptionEnum.NULL_TOKEN_RESPONSE, "Null Token response.");
        }
        if (tokenResponse.get(ACCESS_TOKEN) == null ||
                tokenResponse.get(REFRESH_TOKEN) == null){
            throw new OIDCException(OIDCExceptionEnum.INSUFFICIENT_TOKEN, "Insufficient tokens");
        }
        OIDCTokenTransferObject result = new OIDCTokenTransferObject();
        if (tokenResponse.get(ID_TOKEN) != null && !String.valueOf(tokenResponse.get(ID_TOKEN)).isEmpty()){
            result.setIdToken(String.valueOf(tokenResponse.get(ID_TOKEN)));
        }
        result.setAccessToken(String.valueOf(tokenResponse.get(ACCESS_TOKEN)));
        result.setRefreshToken(String.valueOf(tokenResponse.get(REFRESH_TOKEN)));
        if (tokenResponse.get(EXPIRES_IN) != null){
            result.setExpiresIn(Integer.parseInt(String.valueOf(tokenResponse.get(EXPIRES_IN))));
        }
        if (tokenResponse.get(REFRESH_EXPIRES_IN) != null){
            result.setRefreshExpiresIn(Integer.parseInt(String.valueOf(tokenResponse.get(REFRESH_EXPIRES_IN))));
        }
        return result;
    }

    public synchronized OIDCTokenTransferObject refreshTokens(final String refreshToken) throws OIDCException {
        Map<String, Object> tokenResponse = OIDCUtil.refreshToken(this.restfulUtil, this.oidcConfig, refreshToken);
        if (tokenResponse == null || tokenResponse.isEmpty()){
            throw new OIDCException(OIDCExceptionEnum.NULL_TOKEN_RESPONSE, "Null Token response.");
        }
        if (tokenResponse.get(ACCESS_TOKEN) == null){
            throw new OIDCException(OIDCExceptionEnum.INSUFFICIENT_TOKEN, "Insufficient tokens");
        }
        OIDCTokenTransferObject result = new OIDCTokenTransferObject();
        if (tokenResponse.get(ID_TOKEN) != null && !String.valueOf(tokenResponse.get(ID_TOKEN)).isEmpty()){
            result.setIdToken(String.valueOf(tokenResponse.get(ID_TOKEN)));
        }
        result.setAccessToken(String.valueOf(tokenResponse.get(ACCESS_TOKEN)));
        if (tokenResponse.get(REFRESH_TOKEN) != null && !String.valueOf(tokenResponse.get(REFRESH_TOKEN)).isEmpty()){
            result.setRefreshToken(String.valueOf(tokenResponse.get(REFRESH_TOKEN)));
        }else{
            result.setRefreshToken(refreshToken);
            LogUtil.info("Old refresh token will be reused.", this);
        }
        if (tokenResponse.get(EXPIRES_IN) != null){
            result.setExpiresIn(Integer.parseInt(String.valueOf(tokenResponse.get(EXPIRES_IN))));
        }
        if (tokenResponse.get(REFRESH_EXPIRES_IN) != null){
            result.setRefreshExpiresIn(Integer.parseInt(String.valueOf(tokenResponse.get(REFRESH_EXPIRES_IN))));
        }
        return result;
    }

    /**
     * JWKS 토큰 검증
     * @param token 검증 대상 Token
     * @param checkAud AUD 검증 여부
     * @throws OIDCException 검증이 실패하면 발생하며, 내부적으로 {@link JWKSException}이 발생한다
     */
    @Override
    public void verifyToken(final String token, final boolean checkAud) throws OIDCException {
        try{
            if (checkAud){
                RSAJWKSVerifier.verifyToken(this.restfulUtil, this.oidcConfig.getJwksUri(), token, this.oidcConfig.getClientId());
            }else{
                RSAJWKSVerifier.verifyToken(this.restfulUtil, this.oidcConfig.getJwksUri(), token, null);
            }
        }catch(JWKSException je){
            throw new OIDCException(OIDCExceptionEnum.VERIFY_TOKEN, "JWKS Error:" + je.step.name() + "-" +  je.getMessage());
        }
    }

    @Override
    public long extractAccessTokenExpirationTime(final String accessToken) throws RBACException {
        //-- Extract expiration time for access token.
        Map<String, Claim> accessTokenMap = OIDCUtil.parseJwtPayload(accessToken);
        if (accessTokenMap == null){
            throw new RBACException("Invalid Access Token.");
        }
        //-- Set default AccessTokenExpirationTime.
        long accessTokenExpireTimeoutSec = (System.currentTimeMillis() / 1000) + this.defaultAccessTokenDurationSec;
        Claim expClaim = accessTokenMap.get("exp");
        if (expClaim != null){
            accessTokenExpireTimeoutSec = expClaim.asLong();
            LogUtil.info("Expiration time extracted successfully.(Register):" + accessTokenExpireTimeoutSec, this);
        }
        return accessTokenExpireTimeoutSec;
    }

    @Override
    public long extractRefreshTokenExpirationTime(final String refreshToken) throws RBACException {
        //-- Extract expiration time for refresh token.
        Map<String, Claim> refreshTokenMap = OIDCUtil.parseJwtPayload(refreshToken);
        if (refreshTokenMap == null){
            throw new RBACException("Invalid Refresh Token.");
        }
        long refreshTokenExpireTimeoutSec = (System.currentTimeMillis() / 1000) + this.defaultRefreshTokenDurationSec;
        Claim refTypClaim = refreshTokenMap.get("typ");
        Claim refExpClaim = refreshTokenMap.get("exp");
        if (refTypClaim != null && refExpClaim != null){
            if (refTypClaim.asString().equalsIgnoreCase("OFFLINE")){
                refreshTokenExpireTimeoutSec = Long.MAX_VALUE;
            }else{
                refreshTokenExpireTimeoutSec = refExpClaim.asLong();
            }
        }
        return refreshTokenExpireTimeoutSec;
    }


    /**
     * Outbound IDP Logout을 수행한다.<br>
     * Keycloak의 경우 IDP의 Logout URI로의 Redirect가 수행된다.<br>
     * @param request 서블릿 요청 객체
     * @param response 서블릿 응답 객체
     * @param oidcSessionManager OIDC 세션 관리자. 내부 OIDC Logout을 수행하기 위해 필요.
     * @param clientLogoutAdapter Client Logout Adapter. 내부 OIDC Logout 전/후 처리를 위해 필요.
     * @throws OIDCException OIDC 세션에 ID Token이 없을 경우를 포함한 OIDC 관련 예외 발생 시 던져진다.
     * @throws IOException Redirect 동작이 존재할 경우, 실패 시 발생
     */
    @Override
    public void doOutboundIDPLogout(HttpServletRequest request, HttpServletResponse response,
                                    OIDCSessionManager oidcSessionManager, ClientLogoutAdapter clientLogoutAdapter) throws OIDCException, IOException{
        //-- process manual IDP logout.
        //-- 사용자에 의한 직접적인 Outbound Logout은 세션의 쿠키가 유지됨.
        String sessionId = OIDCUtil.getCookieValue(request, OIDCConstants.COOKIE_NAME);
        OIDCSession sObj = oidcSessionManager.getSessionBySessionID(sessionId);
        if (sObj == null) {
            throw new OIDCException(OIDCExceptionEnum.OIDC_SESSION_EXCEPTION, "Not found session.");
        }
        //-- invalidate OIDC Session and legacy Session.
        OIDCUtil.doLogout(sObj.getSid(), request, response, oidcSessionManager,clientLogoutAdapter,true);
        // NOSONAR String postLogoutRedirectUrl = OIDCUtil.buildFullUrl(request, this.oidcConfig.getPostLogoutUri());
        String postLogoutRedirectUrl = this.oidcConfig.getPostLogoutUri();
        String idTokenHint = sObj.getTokens().getIDToken();
        if (idTokenHint == null || idTokenHint.isEmpty()) {
            LogUtil.error("Id Token Not found.", this);
            throw new OIDCException(OIDCExceptionEnum.INSUFFICIENT_TOKEN, "Not found ID token.");
        }
        String logoutUri = this.oidcConfig.getLogoutUri() + "?client_id=" + this.oidcConfig.getClientId() +
                "&post_logout_redirect_uri=" + postLogoutRedirectUrl +
                "&id_token_hint=" + idTokenHint;
        response.sendRedirect(logoutUri);
    }

    /**
     * Inbound IDP Logout에 대응하여 수행.<br>
     * Keycloak의 경우 Post/Get Method에 따라 Front/Back Channel Logout 여부가 결정된다.<br>
     * @param request 서블릿 요청 객체
     * @param response 서블릿 응답 객체
     * @param oidcSessionManager OIDC 세션 관리자. 내부 OIDC Logout을 수행하기 위해 필요.
     * @param clientLogoutAdapter Client Logout Adapter. 내부 OIDC Logout 전/후 처리를 위해 필요.
     * @throws OIDCException Logout Token 검증 실패 또는 각종 로그아웃 관련 예외 발생 시 던져진다
     */
    @Override
    public void doInboundIDPLogout(HttpServletRequest request, HttpServletResponse response,
                                   OIDCSessionManager oidcSessionManager, ClientLogoutAdapter clientLogoutAdapter) throws OIDCException{
        if (request.getMethod().equals(HttpMethod.POST.name())) {
            //-- process IDP Back Channel logout.
            //-- Back Channel logout.
            String logoutToken = request.getParameter("logout_token");
            if (logoutToken == null){
                LogUtil.error("No logout token received.", this);
                throw new OIDCException(OIDCExceptionEnum.NULL_LOGOUT_TOKEN, "No logout token");
            }
            this.verifyToken(logoutToken, false);
            String sid = KeycloakUtil.extractSidFromLogoutToken(logoutToken);
            if (oidcSessionManager.getSessionBySID(sid) == null){
                LogUtil.info("[" + sid + "] Already logged out.", this);
            }else{
                OIDCUtil.doLogout(sid, request, response,oidcSessionManager,clientLogoutAdapter,false);
                LogUtil.info("OIDC Session and client Session has been removed successfully.(Lazy)", this);
            }
        } else if (request.getMethod().equals(HttpMethod.GET.name())) {
            //-- process IDP Front Channel logout. Not recommended because there is no source verification.
            //-- Front Channel logout.
            String sid = request.getParameter("sid");
            if (sid == null){
                throw new OIDCException(OIDCExceptionEnum.NULL_LOGOUT_TOKEN, "No SID in front channel logout msg.");
            }
            if (oidcSessionManager.getSessionBySID(sid) == null){
                LogUtil.info("[" + sid + "] Already logged out.", this);
            }else{
                OIDCUtil.doLogout(sid, request, response,oidcSessionManager,clientLogoutAdapter,false);
                LogUtil.info("OIDC Session and client Session has been removed successfully.(Lazy)", this);
            }
        } else {
            LogUtil.error("Not supported method:" + request.getMethod(), this);
        }
    }
}
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
import io.github.sbeholder32167.oidctemplate.client.exception.RBACException;
import io.github.sbeholder32167.oidctemplate.client.provider.AbstractOIDCProvider;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSession;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSessionManager;
import io.github.sbeholder32167.oidctemplate.client.session.storage.OIDCAuthParameterStorage;
import io.github.sbeholder32167.oidctemplate.client.tokens.OIDCTokens;
import io.github.sbeholder32167.oidctemplate.client.tokens.impl.NaverTokens;
import io.github.sbeholder32167.oidctemplate.exception.OIDCException;
import io.github.sbeholder32167.oidctemplate.exception.OIDCExceptionEnum;
import io.github.sbeholder32167.oidctemplate.jwks.RSAJWKSVerifier;
import io.github.sbeholder32167.oidctemplate.jwks.exception.JWKSException;
import io.github.sbeholder32167.oidctemplate.rest.RestfulUtil;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import io.github.sbeholder32167.oidctemplate.util.OIDCUtil;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Naver 인증 제공자 Class.<br>
 *
 * <p>Naver Social Login에 필요한 동작 및 각종 Parameter와 Logic이 정의된 Class.<br>
 * Naver 특성(토큰 구조, 파라미터명 등)이 반영되었다.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-09-03
 */
//-- XML Bean 등록
public class NaverProvider extends AbstractOIDCProvider {
    public NaverProvider(OIDCConfig config, RestfulUtil restfulUtil, OIDCAuthParameterStorage oidcAuthParameterStorage) {
        super(config, restfulUtil, oidcAuthParameterStorage);
    }

    @Override
    public void redirectIDPAuthPage(HttpServletRequest request, HttpServletResponse response, String redirectUri) throws OIDCException, IOException {
        String redirectUrl;
        if (redirectUri == null){
            redirectUrl = this.oidcConfig.getRedirectUri();
        }else{
            redirectUrl = OIDCUtil.buildFullUrl(request, redirectUri);
        }
        String sessionId = OIDCUtil.extractSessionId(request);
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
    public OIDCDataTransferObject checkParameters(HttpServletRequest request) throws OIDCException {
        String state = request.getParameter("state");
        String code = request.getParameter("code");
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
        result.setSessionState("");
        //-- 만약 보안을 위해 Session을 refresh할 경우, 여기서 session Id를 넣는 것은 무의미하다.
        // NOSONAR result.setSessionId(sessionId);
        return result;
    }

    @Override
    public OIDCTokenTransferObject acquireTokens(OIDCDataTransferObject dto, String redirectUri) throws OIDCException {
        Map<String, Object> tokenResponse = OIDCUtil.exchangeCodeForToken(
                this.restfulUtil, this.oidcConfig,
                dto.getCode(), dto.getCodeVerifier(), dto.getState(), "", dto.getScope(),
                redirectUri);
        if (tokenResponse == null || tokenResponse.isEmpty()){
            throw new OIDCException(OIDCExceptionEnum.NULL_TOKEN_RESPONSE, "Null Token response.");
        }
        if (!tokenResponse.containsKey(ACCESS_TOKEN)){
            throw new OIDCException(OIDCExceptionEnum.INSUFFICIENT_TOKEN, "Insufficient tokens");
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
        if (tokenResponse.containsKey(REFRESH_EXPIRES_IN)){
            result.setRefreshExpiresIn(Integer.parseInt(String.valueOf(tokenResponse.get(REFRESH_EXPIRES_IN))));
        }else{
            //-- 90 days as Naver Refresh Token life span.
            result.setRefreshExpiresIn(86400 * 90);
        }
        return result;
    }

    @Override
    public OIDCTokenTransferObject refreshTokens(String refreshToken) throws OIDCException {
        if (refreshToken == null || refreshToken.isEmpty()){
            LogUtil.info("Not available refresh token.", this);
            throw new OIDCException(OIDCExceptionEnum.INSUFFICIENT_TOKEN, "Not available refresh token.");
        }
        Map<String, Object> tokenResponse = OIDCUtil.refreshToken(this.restfulUtil, this.oidcConfig, refreshToken);
        if (tokenResponse == null || tokenResponse.isEmpty()){
            throw new OIDCException(OIDCExceptionEnum.NULL_TOKEN_RESPONSE, "Null Token response.");
        }
        if (!tokenResponse.containsKey(ACCESS_TOKEN) || !tokenResponse.containsKey(EXPIRES_IN)){
            throw new OIDCException(OIDCExceptionEnum.INSUFFICIENT_TOKEN, "Insufficient tokens");
        }
        OIDCTokenTransferObject result = new OIDCTokenTransferObject();
        result.setAccessToken(String.valueOf(tokenResponse.get(ACCESS_TOKEN)));
        result.setExpiresIn(Integer.parseInt(String.valueOf(tokenResponse.get(EXPIRES_IN))));
        //-- not refreshing Refresh token.
        LogUtil.info("Old refresh token will be reused.", this);
        return result;
    }

    @Override
    public void verifyToken(OIDCTokenTransferObject tto) throws OIDCException {
        try{
            //-- Key Set에 alg Claim이 없는 특이한 형태. 그래서 alg Check를 Skip.
            RSAJWKSVerifier.verifyToken(this.restfulUtil, this.oidcConfig.getJwksUri(), tto.getIdToken(), this.oidcConfig.getClientId(), true);
        }catch(JWKSException je){
            throw new OIDCException(OIDCExceptionEnum.VERIFY_TOKEN, "JWKS Error:" + je.step.name() + "-" +  je.getMessage());
        }
    }

    @Override
    public OIDCTokens generateTokens(OIDCTokenTransferObject tto) throws RBACException {
        return new NaverTokens(tto);
    }

    @Override
    public void doOutboundIDPLogout(HttpServletRequest request, HttpServletResponse response,
                                    OIDCSessionManager oidcSessionManager, ClientLogoutAdapter clientLogoutAdapter) throws OIDCException, IOException{
        //-- Naver는 IDP 동시 Logout을 지원하지 않음. Naver Works는 가능.
        String sessionId = OIDCUtil.getCookieValue(request, OIDCConstants.COOKIE_NAME);
        OIDCSession sObj = oidcSessionManager.getSessionBySessionID(sessionId);
        if (sObj == null) {
            throw new OIDCException(OIDCExceptionEnum.OIDC_SESSION_EXCEPTION, "Not found session.");
        }
        //-- Naver Provider의 경우 Token revoke만 존재
        this.revokeToken(sObj.getTokens().getAccessToken(), "access_token");
        if (sObj.getTokens().getRefreshToken() != null && !sObj.getTokens().getRefreshToken().isEmpty()){
            this.revokeToken(sObj.getTokens().getRefreshToken(), "refresh_token");
        }
        //-- invalidate OIDC Session and legacy Session.
        OIDCUtil.doLogout(sObj.getSid(), request, response, oidcSessionManager,clientLogoutAdapter,true);

        // NOSONAR String postLogoutRedirectUrl = OIDCUtil.buildFullUrl(request, this.oidcConfig.getPostLogoutUri());
        String postLogoutRedirectUrl = this.oidcConfig.getPostLogoutUri();
        response.sendRedirect(postLogoutRedirectUrl);
    }

    @Override
    public void doInboundIDPLogout(HttpServletRequest request, HttpServletResponse response,
                                   OIDCSessionManager oidcSessionManager, ClientLogoutAdapter clientLogoutAdapter) throws OIDCException{
        /* Not implemented : Naver Provider는 IDP 동시 Logout Order를 내리지 않는다. */
    }

    /**
     * 토큰 취소 처리
     * @param token Access Token ,Refresh Token.
     */
    private void revokeToken(final String token, final String token_type_hint){
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        Map<String, String> bodyParam = new HashMap<String, String>();
        bodyParam.put("token", token);
        bodyParam.put("token_type_hint", token_type_hint);
        bodyParam.put("client_id", this.oidcConfig.getClientId());
        bodyParam.put("client_secret", this.oidcConfig.getClientSecret());
        ResponseEntity<Map> responseEntity = this.restfulUtil.doRestful(this.oidcConfig.getRevokeEndpoint(), HttpMethod.POST ,httpHeaders, bodyParam, Map.class);
        if(responseEntity.getStatusCode().value() != 200){
            Map body = responseEntity.getBody();
            if (body != null){
                String errorStr = String.valueOf(body.get("error"));
                String errorDescStr = String.valueOf(body.get("error_description"));
                LogUtil.error("Error:" + errorStr + " " + errorDescStr, this);
            }else{
                LogUtil.error("Error:" + responseEntity.getStatusCode().value(), this);
            }
        }else{
            LogUtil.info("The token has been revoked successfully.", this);
        }
    }
}

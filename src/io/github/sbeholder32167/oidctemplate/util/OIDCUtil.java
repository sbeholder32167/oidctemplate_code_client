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
package io.github.sbeholder32167.oidctemplate.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import io.github.sbeholder32167.oidctemplate.OIDCConstants;
import io.github.sbeholder32167.oidctemplate.adapter.ClientLogoutAdapter;
import io.github.sbeholder32167.oidctemplate.exception.OIDCException;
import io.github.sbeholder32167.oidctemplate.exception.OIDCExceptionEnum;
import io.github.sbeholder32167.oidctemplate.client.OIDCConfig;
import io.github.sbeholder32167.oidctemplate.client.OIDCTokenTransferObject;
import io.github.sbeholder32167.oidctemplate.client.tokens.OIDCTokens;
import io.github.sbeholder32167.oidctemplate.client.provider.OIDCProvider;
import io.github.sbeholder32167.oidctemplate.rest.RestfulUtil;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSession;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSessionManager;
import org.springframework.http.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * OIDC 인증 및 동작에 관련된 공통 메서드 모음.<br>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-22
 */
public class OIDCUtil {
    private OIDCUtil() {}

    private static final SecureRandom secureRandom = new SecureRandom();
    /**
     * State를 생성한다.
     * @return State 문자열
     */
    public static String generateState() {
        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
    /**
     * URI 패스를 기반으로 완전한 URL 주소를 빌드
     * @param request 현재 인입된 HTTP 요청 객체
     * @param uriPath 결합할 엔드포인트 URI 패스 (예: "/auth/oidc/callback")
     * @return 완성된 URL 문자열
     */
    public static String buildFullUrl(HttpServletRequest request, String uriPath) {
        String scheme = request.getScheme();
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();

        StringBuilder urlBuilder = new StringBuilder();
        urlBuilder.append(scheme).append("://").append(serverName);
        if (("http".equals(scheme) && serverPort != 80) || ("https".equals(scheme) && serverPort != 443)) {
            urlBuilder.append(":").append(serverPort);
        }

        if (!uriPath.startsWith("/")) {
            urlBuilder.append("/");
        }
        urlBuilder.append(request.getContextPath());
        urlBuilder.append(uriPath);
        return urlBuilder.toString();
    }

    /**
     * PKCE-Code Verifier 생성
     * @return Code Verifier
     */
    public static String generateCodeVerifier() {
        byte[] codeVerifier = new byte[32]; // 32바이트의 난수 생성
        secureRandom.nextBytes(codeVerifier);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
    }

    /**
     * PKCE-Code Challenge 생성
     * @param codeVerifier Code Verifier
     * @return Code Challenge(SHA-256)
     */
    public static String generateCodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256", e);
        }
    }

    /**
     * SecureRandom을 이용하여 AES256 Key를 생성
     * @return Key bytes
     */
    public static byte[] generateSecretKeyForRefreshTokenEncrypt(){
        byte[] secretKey = new byte[32];
        secureRandom.nextBytes(secretKey);
        return secretKey;
    }

    /**
     * 주어진 서블릿 요청 객체에서 Session ID를 추출한다.<br>
     * JSESSIONID Cookie 값이 세션 추출 과정에서 변경되지 말아야 할 경우 이용.<br>
     * @param request 서블릿 요청 객체
     * @return Session ID
     * @throws OIDCException 주어진 요청에서 세션이 없을 경우 발생.
     */
    public static String extractSessionId(final HttpServletRequest request) throws OIDCException {
        HttpSession session = request.getSession(false);
        if (session == null){
            throw new OIDCException(OIDCExceptionEnum.REQ_SESSION_EXCEPTION, "Null Session");
        }
        return session.getId();
    }

    /**
     * Token Endpoint에 요청하여 Token을 받아온다.
     * @param restUtil RestfulUtil Object.
     * @param config OIDCConfig bean.
     * @param code 인증 완료 코드
     * @param codeVerifier PKCE Code Verifier
     * @param sessionState 인증 후 리턴되는 State.
     * @return JWKS 검증이 되지 않은 토큰<br>id_token, access_token, refresh_token<br>Nullable
     */
    public static Map<String, Object> exchangeCodeForToken(final RestfulUtil restUtil, final OIDCConfig config,
                                                     String code, String codeVerifier, String state,
                                                     String sessionState, String scope, String redirectUri) {
        //-- Access Token과 idToken을 받아온다..
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        Map<String, String> bodyParams = new HashMap<>();
        bodyParams.put("grant_type","authorization_code");
        bodyParams.put("code",code);
        bodyParams.put("session_state",sessionState);
        bodyParams.put("state",state);
        bodyParams.put("client_id", config.getClientId());
        bodyParams.put("client_secret",config.getClientSecret());
        bodyParams.put("code_verifier", codeVerifier);
        if (redirectUri == null){
            bodyParams.put("redirect_uri",config.getRedirectUri());
        }else{
            bodyParams.put("redirect_uri",redirectUri);
        }
        bodyParams.put("scope", scope.replace(","," "));
        String tokenEndpoint = config.getTokenEndpoint();
        ResponseEntity<Map> response = restUtil.doRestful(tokenEndpoint, HttpMethod.POST, headers, bodyParams, Map.class);
        HttpStatus resCode = response.getStatusCode();
        if (resCode == HttpStatus.OK){
            Map<String, Object> result = new HashMap<>();
            for(Object rawK : response.getBody().keySet()){
                result.put(String.valueOf(rawK), response.getBody().get(rawK));
            }
            return result;
        }else{
            LogUtil.error("Token request has failed:" + resCode.value(), OIDCUtil.class.getName());
            return null;
        }
    }

    /**
     * 토큰 갱신
     * @param restUtil RestfulUtil Object.
     * @param config OIDCConfig bean.
     * @param refreshToken Refresh Token
     * @return JWKS 검증이 되지 않은 토큰<br>id_token, access_token, refresh_token<br>Nullable
     */
    public static Map<String, Object> refreshToken(final RestfulUtil restUtil, final OIDCConfig config,
                                                   final String refreshToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        Map<String, String> bodyParams = new HashMap<>();
        bodyParams.put("grant_type","refresh_token");
        bodyParams.put("refresh_token",refreshToken);
        bodyParams.put("client_id", config.getClientId());
        bodyParams.put("client_secret",config.getClientSecret());
        bodyParams.put("scope", config.getScope().replace(","," "));
        String tokenEndpoint = config.getTokenEndpoint();
        ResponseEntity<Map> response = restUtil.doRestful(tokenEndpoint, HttpMethod.POST, headers, bodyParams, Map.class);
        HttpStatus resCode = response.getStatusCode();
        if (resCode == HttpStatus.OK){
            Map<String, Object> result = new HashMap<>();
            for(Object rawK : response.getBody().keySet()){
                result.put(String.valueOf(rawK), response.getBody().get(rawK));
            }
            return result;
        }else{
            LogUtil.error("Token(Refresh) request has failed:" + resCode.value(), OIDCUtil.class.getName());
            return null;
        }
    }
    /**
     * JWT를 파싱하여 Map의 형태로 Claim들을 제공
     * @param tokenStr JSON Web Token.
     * @return Token Map
     */
    public static Map<String, Claim> parseJwtPayload(String tokenStr) {
        try{
            return JWT.decode(tokenStr).getClaims();
        }catch(JWTDecodeException je){
            LogUtil.error("JWT Decode Exception:" + je.getLocalizedMessage(), OIDCUtil.class.getName());
            return null;
        }
    }

    /**
     * OIDC Session Logout 처리.<br> Client Legacy Session의 만료처리도 같이 진행.
     * 세션을 무효화 시킨 후, client Logout Adapter의 doJobPostLogout을 주어진 postLogoutParam과 함께 실행시킨다.<br>
     * @param sid Session ID. IDP에서 발급한 세션 식별자.
     * @param request 서블릿 요청 객체
     * @param response 서블릿 응답 객체
     * @param sessionManager OIDC Session Storage Bean
     * @param clientLogoutAdapter OIDCLogoutAdapter. Nullable.
     */
    public static void doLogout(final String sid,
                                HttpServletRequest request, HttpServletResponse response,
                                OIDCSessionManager sessionManager, ClientLogoutAdapter clientLogoutAdapter, boolean isNow) throws OIDCException {
        if (sid == null || sid.isEmpty()){
            throw new OIDCException(OIDCExceptionEnum.NULL_SESSION_ID, "No Session Id");
        }
        //-- Logout에서는 사용자에 의한 쿠키가 전달되지 않을 때도 있다.
        OIDCSession session;
        if (request.getSession(false) == null){
            session = sessionManager.getSessionBySID(sid);
        }else{
            String sessionId = OIDCUtil.getCookieValue(request, OIDCConstants.COOKIE_NAME);
            session = sessionManager.getSessionBySessionID(sessionId);
        }
        if (session == null){
            throw new OIDCException(OIDCExceptionEnum.REQ_SESSION_EXCEPTION, "Null Session.");
        }
        if (clientLogoutAdapter != null){
            clientLogoutAdapter.doJobBeforeLogout(request, response ,session.getTokens());
        }
        sessionManager.expireSession(request, response, sid, isNow);
        if (clientLogoutAdapter != null){
            clientLogoutAdapter.doJobPostLogout(response ,session.getTokens());
        }
    }

    /**
     * 세션 내 토큰을 갱신
     * @param oidcSession OIDC Session
     * @param oidcProvider OIDC Provider (Keycloak ...)
     * @throws OIDCException Access / Refresh Token의 파싱 실패 또는 null.
     */
    public static void refreshTokenInSession(OIDCSession oidcSession, OIDCProvider oidcProvider) throws OIDCException {
        LogUtil.info("checked token that needed to refresh:" + oidcSession.getSid(), OIDCUtil.class.getName());
        OIDCTokens tObj = oidcSession.getTokens();
        try {
            OIDCTokenTransferObject tto = oidcProvider.refreshTokens(tObj.getRefreshToken());
            if (tto.getAccessToken() == null || tto.getAccessToken().isEmpty()){
                LogUtil.error( "Auto token refresh has been failed. No Access Token", OIDCUtil.class.getName());
            }else{
                tObj.setAccessToken(tto.getAccessToken());
                long newTokenExpirationTimeSec = oidcProvider.extractAccessTokenExpirationTime(tto.getAccessToken());
                oidcSession.setAccessTokenExpirationTimeSec(newTokenExpirationTimeSec);
                LogUtil.info("Expiration time extracted successfully(Auto Refreshed):" + newTokenExpirationTimeSec, OIDCUtil.class.getName());
            }
            if (tto.getRefreshToken() != null && !tto.getRefreshToken().isEmpty()){
                tObj.setRefreshToken(tto.getRefreshToken());
                long newTokenExpirationTimeSec = oidcProvider.extractRefreshTokenExpirationTime(tto.getRefreshToken());
                oidcSession.setRefreshTokenExpirationTimeSec(newTokenExpirationTimeSec);
                LogUtil.info("Expiration time in Refresh token extracted successfully(Auto Refreshed):" + newTokenExpirationTimeSec, OIDCUtil.class.getName());
            }
            oidcSession.setLatestIdptouchTimeSec(System.currentTimeMillis() / 1000);
        } catch (OIDCException e) {
            LogUtil.error("Auto token refresh has been failed:" + oidcSession.getSid() + " : " + e.getLocalizedMessage(), OIDCUtil.class.getName());
            if (e.getStep() == OIDCExceptionEnum.NULL_TOKEN_RESPONSE){
                throw e;
            }
        }
    }

    /**
     * 주어진 서블릿 요청에서 해당 Cookie Key의 값을 추출한다
     * @param request 서블릿 요청 객체
     * @param cookieKey Cookie Key 문자열
     * @return 없을 경우 빈칸을 리턴한다.
     */
    public static String getCookieValue(HttpServletRequest request, final String cookieKey){
        String cookieKeyStr;
        if (cookieKey == null || cookieKey.isEmpty()){
            cookieKeyStr = "JSESSIONID";
        }else{
            cookieKeyStr = cookieKey;
        }
        String targetCookieValue = "";
        Cookie[] cookies = request.getCookies(); // 또는 그냥 request.getCookies()
        if (request.getCookies() != null) {
            for (Cookie cookie : cookies) {
                if (cookieKeyStr.equals(cookie.getName())) {
                    targetCookieValue = cookie.getValue();
                    break;
                }
            }
        }
        return targetCookieValue;
    }
}
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

import io.github.sbeholder32167.oidctemplate.adapter.ClientLegacySessionAdapter;
import io.github.sbeholder32167.oidctemplate.client.provider.OIDCProvider;
import io.github.sbeholder32167.oidctemplate.client.session.refresh.OIDCAutoTokenChecker;
import io.github.sbeholder32167.oidctemplate.client.session.refresh.impl.IdpTimeoutAutoTokenChecker;
import io.github.sbeholder32167.oidctemplate.exception.OIDCException;
import io.github.sbeholder32167.oidctemplate.exception.OIDCExceptionEnum;
import io.github.sbeholder32167.oidctemplate.client.tokens.OIDCTokens;
import io.github.sbeholder32167.oidctemplate.client.exception.RBACException;
import io.github.sbeholder32167.oidctemplate.client.session.duplicatepolicy.OIDCSessionDuplicatePolicy;
import io.github.sbeholder32167.oidctemplate.client.session.registry.OIDCSessionRegistry;
import io.github.sbeholder32167.oidctemplate.client.session.storage.OIDCAuthParameterStorage;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import io.github.sbeholder32167.oidctemplate.util.OIDCUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OIDC Session Manager Class.<br>
 *
 * OIDC-Legacy Session Facade.<br>
 * OIDC 세션 및 Legacy 세션을 동시 관리.<br>
 * Logout 및 인가 등 Template Code 전체적으로 사용됨.<br>
 * 세션 timeout에 따른 만료 동작 및 자동 토큰 갱신 동작은 각 OIDC Session Registry/Repository 구현체에서 처리.<br>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-06-21
 */
//-- XML Bean 등록
public class OIDCSessionManager {
    private final OIDCProvider oidcProvider;
    private final OIDCSessionRegistry oidcSessionRegistry;
    private final OIDCAuthParameterStorage oidcAuthParameterStorage;
    private final ClientLegacySessionAdapter clientLegacySessionAdapter;
    public OIDCSessionManager(OIDCProvider oidcProvider,
                              OIDCSessionRegistry oidcSessionRegistry,
                              OIDCAuthParameterStorage oidcAuthParameterStorage,
                              ClientLegacySessionAdapter clientLegacySessionAdapter){
        this.oidcProvider = oidcProvider;
        this.oidcSessionRegistry = oidcSessionRegistry;
        this.oidcAuthParameterStorage = oidcAuthParameterStorage;
        this.clientLegacySessionAdapter = clientLegacySessionAdapter;
    }

    /**
     * 세션 중복 정책 구현체 설정. (Optional)<br>
     * Spring Security의 중복 제어를 따르려면 이것을 설정하지 말아야 한다.<br>
     * 단, 그때는 Spring Security의 SessionRegistry 인터페이스를 구현한 Bridge Bean을 등록하여 OIDC Session과 동기화 되도록 해야 한다<br>
     */
    private OIDCSessionDuplicatePolicy oidcSessionDuplicatePolicy;
    /**
     * 세션 중복 정책 구현체 설정. (Optional)<br>
     * @param duplicatePolicy 세션 중복 제어 정책 구현체
     */
    public void setSessionDuplicatePolicy(OIDCSessionDuplicatePolicy duplicatePolicy){
        this.oidcSessionDuplicatePolicy = duplicatePolicy;
    }

    /**
     * OIDC Session Timeout.
     */
    protected int timeoutSec = 1800;
    public void setTimeoutSec(final int sec){
        this.timeoutSec = sec;
    }
    /**
     * IDP Session Timeout.<br>
     * 이것을 이용하여 IDP 세션의 Timeout이 설정되는 것은 아니다. 그냥 참조값<br>
     * OIDC Session Timeout과 같게 하는 것을 권장<br>
     */
    protected int idpSessionTimeoutSec = 1800;
    public void setIdpSessionTimeoutSec(final int sec){ this.idpSessionTimeoutSec = sec; }

    /**
     * 토큰 만료 전 갱신을 위한 여유 시간(초)<br>
     * 5분짜리 Access Token의 경우, 만료 시각이 이값보다 적게 남았다면 갱신 동작을 진행<br>
     */
    private int skewSec = 60;
    public void setSkewSec(final int skewSec){
        this.skewSec = skewSec;
    }
    /**
     * 토큰 자동 갱신 여부 판정 구현체. (Optional)<br>
     * Default : IDP Timeout Checker
     */
    private OIDCAutoTokenChecker autoTokenChecker = new IdpTimeoutAutoTokenChecker();
    /**
     * 토큰 자동 갱신 여부 판정 구현체 설정. (Optional)<br>
     * @param autoTokenChecker 토큰 자동 갱신 여부 판정 구현체
     */
    public void setAutoTokenChecker(OIDCAutoTokenChecker autoTokenChecker){
        this.autoTokenChecker = autoTokenChecker;
    }

    /**
     * OIDC 세션을 등록.<br>
     * Legacy 세션 등록 메서드인 setSession과 통합하고 싶었으나 파라미터가 {@link ClientLegacySessionAdapter}의 setSession 파라미터와 다름.<br>
     * 또한, Spring Security의 Filter / Provider를 이용하는 경우, setSession을 호출할 필요가 없음.<br>
     * (AbstractAuthenticationProcessingFilter의 doFilter에서 해줌)<br>
     * 등록시에는, 호출하는 측에서 (Filter, Controller, OIDCUtil) 따로 호출하는 것으로 정의함.<br>
     * @param sid ID Token의 SID Claim
     * @param sessionId 요청 객체의 세션 ID. JSESSIONID를 사용할 경우 request.getSession().getId()
     * @param tokens 인증 객체
     * @throws OIDCException 세션 중복에 따른 예외
     */
    public synchronized void registerOIDCSession(final String sid, final String sessionId, OIDCTokens tokens) throws OIDCException{
        if (this.oidcSessionDuplicatePolicy != null && tokens.getDuplicateCheckKey() != null){
            try {
                this.oidcSessionDuplicatePolicy.onDuplicateOIDCSession(tokens.getDuplicateCheckKey(),
                                                                       this.oidcSessionRegistry);
            }catch(RBACException re){
                throw new OIDCException(OIDCExceptionEnum.OIDC_SESSION_DUPLICATE, "Another session exists.");
            }
        }
        this.oidcAuthParameterStorage.removeRequestParameterAdapter(sessionId);
        long accessTokenExpireTimeoutSec = -1;
        long refreshTokenExpireTimeoutSec = -1;
        try{
            accessTokenExpireTimeoutSec = this.oidcProvider.extractAccessTokenExpirationTime(tokens.getAccessToken());
            refreshTokenExpireTimeoutSec = this.oidcProvider.extractRefreshTokenExpirationTime(tokens.getRefreshToken());
        }catch(RBACException re){
            LogUtil.error("Failed to extract Access / Refresh Token expiration timeout from tokens.", this);
        }
        this.oidcSessionRegistry.register(sid, tokens.getDuplicateCheckKey(), sessionId, tokens, this.timeoutSec, accessTokenExpireTimeoutSec, refreshTokenExpireTimeoutSec);
    }

    /**
     * Legacy 세션을 등록<br>
     * OIDC 세션 등록 시 이 메서드를 반드시 호출<br>
     * Spring Security Filter / Provider 사용 시 호출 필요 없음.<br>
     * @param request 서블릿 요청 객체
     * @param response 서블릿 응답 객체
     * @param legacySessionObj Legacy Session Object. AuthConvertAdapter를 거친 인증 객체
     */
    public synchronized void registerLegacySession(HttpServletRequest request, HttpServletResponse response, Object legacySessionObj){
        this.clientLegacySessionAdapter.setSession(request, response, legacySessionObj, false, null);
    }

    /**
     * 세션 만료 처리.<br>
     * 주로 IDP Logout에서 사용된다<br>
     * @param request 서블릿 요청 객체
     * @param response 서블릿 응답 객체
     * @param sid SID Claim 값
     * @param isNow 즉시 적용 여부를 설정. true일 경우 바로 OIDC 세션을 삭제, false일 경우 Interceptor에서 lazy 삭제.
     * @throws OIDCException 서블릿 세션 무력화 예외 발생 시
     */
    public synchronized void expireSession(HttpServletRequest request, HttpServletResponse response,
                                           final String sid, boolean isNow) throws OIDCException{
        OIDCSession sObj;
        if (request.getSession(false) == null){
            sObj = this.oidcSessionRegistry.getSessionBySID(sid);
        }else{
            String sessionId = OIDCUtil.extractSessionId(request);
            sObj = this.oidcSessionRegistry.getSessionBySessionId(sessionId);
        }
        if (sObj != null){
            this.oidcAuthParameterStorage.removeRequestParameterAdapter(sObj.getSessionId());
            this.oidcSessionRegistry.invalidateSession(sid, sObj.getSessionId(), isNow);
            this.clientLegacySessionAdapter.invalidateSession(request, response, null);
        }
    }

    /**
     * HttpSessionListener 구현체에서 호출하며 Session을 만료시켜주는 메서드<br>
     * @param sessionId 요청 객체의 세션 ID. JSESSIONID를 사용할 경우 request.getSession().getId()
     */
    public synchronized void expireSessionByEventListener(final String sessionId){
        OIDCSession sObj = this.oidcSessionRegistry.getSessionBySessionId(sessionId);
        if (sObj != null){
            this.oidcAuthParameterStorage.removeRequestParameterAdapter(sObj.getSessionId());
            this.oidcSessionRegistry.invalidateSession(sObj.getSid(), sObj.getSessionId(), true);
            LogUtil.info("[" + sessionId + "] has been invalidated successfully.", this);
        }else{
            LogUtil.info("Null Session. The session may have already been removed.", this);
        }
    }

    /**
     * OIDC 세션의 유지 관리.<br>
     * OIDC Session Interceptor에서 인증된 요청의 유입 시 호출된다.<br>
     * 1. OIDC 세션의 Timeout을 확인하고 그에 따른 동작 실행.<br>
     * (Timeout일 경우 만료시키며, Timeout이 아닐경우 OIDC 세션 수명을 연장시킨다)<br>
     * 2. Auto Token Checker가 Bean으로 등록된 경우 Token 갱신 여부를 확인하고 필요시 Token의 갱신을 IDP로 요청한다.<br>
     * @param oidcSession OIDC 세션 객체.
     * @throws OIDCException OIDC Session이 Timeout으로 인해 이미 만료처리(Lazy) 되었을 경우 던져진다.
     */
    public void maintainSession(final OIDCSession oidcSession) throws OIDCException{
        try {
            this.oidcSessionRegistry.checkSessionTimeout(oidcSession, this.timeoutSec);
        }catch (OIDCException e){
            LogUtil.info(e.getMessage(), this);
            throw e;
        }
        //-- Auto Token refresh if required.
        if (this.autoTokenChecker != null){
            try {
                if (this.autoTokenChecker.needToRefreshTokens(oidcSession, this.idpSessionTimeoutSec, this.skewSec)){
                    LogUtil.info("tokens refreshed - " + oidcSession.getSid(), this);
                    OIDCUtil.refreshTokenInSession(oidcSession, this.oidcProvider);
                }else{
                    LogUtil.info("No needed to refresh tokens.", this);
                }
            }catch (OIDCException oe){
                if (oe.getStep() == OIDCExceptionEnum.NULL_TOKEN_RESPONSE){
                    LogUtil.error("Null token accepted while refresh tokens.", this);
                    this.oidcSessionRegistry.invalidateSession(oidcSession.getSid(), oidcSession.getSessionId(), false);
                }
            }
        }
    }

    /**
     * 새로운 Access / Refresh Token을 저장한다.<br>
     * 두 토큰 파라미터 모두 null이면 아무런 동작도 하지 않도록 구현.<br>
     * Refresh Token을 이용한 갱신 Mechanism.<br>
     * IDP측으로의 Action에 대한 결과이므로, IDP 세션의 최근 접근 시각을 업데이트할 좋은 시점이 된다.<br>
     * IDP 세션의 최근 접근 시각을 이용한 메커니즘 구현 시, 반드시 여기에 갱신 로직이 포함되어야 한다<br>
     * @param sessionId 요청 객체의 세션 ID. JSESSIONID를 사용할 경우 request.getSession().getId()
     * @param newAccessToken 새로운 Access Token 문자열(base64). Nullable.
     * @param newRefreshToken 새로운 Refresh Token 문자열(base64). Nullable.
     * @throws OIDCException 인증 객체를 불러오지 못했거나, 기타 내부 예외 발생시 던져진다
     */
    public void setNewToken(final String sessionId, final String newAccessToken, final String newRefreshToken) throws OIDCException{
        if ((newAccessToken == null || newAccessToken.isEmpty())
                && (newRefreshToken == null || newRefreshToken.isEmpty())){
            LogUtil.error("Required parameters not available." ,this);
            return;
        }
        OIDCSession sObj = this.oidcSessionRegistry.getSessionBySessionId(sessionId);
        if (sObj == null){
            throw new OIDCException(OIDCExceptionEnum.REFRESH_ACCESS_TOKEN, "No session available.");
        }
        //-- update IDP Server Access time.
        sObj.setLatestIdptouchTimeSec(System.currentTimeMillis() / 1000);
        //-- parsing Tokens.
        OIDCTokens targetTokens = sObj.getTokens();
        if (newAccessToken != null && !newAccessToken.isEmpty()){
            targetTokens.setAccessToken(newAccessToken);
            long newAccessTokenExpirationTimeSec = this.oidcProvider.extractAccessTokenExpirationTime(newAccessToken);
            sObj.setAccessTokenExpirationTimeSec(newAccessTokenExpirationTimeSec);
            LogUtil.info("Expiration time in new access token has been extracted successfully(Refreshed):" + newAccessTokenExpirationTimeSec, this);
        }
        if (newRefreshToken != null && !newRefreshToken.isEmpty()){
            targetTokens.setRefreshToken(newRefreshToken);
            long refreshTokenExpirationTimeSec = this.oidcProvider.extractRefreshTokenExpirationTime(newRefreshToken);
            sObj.setRefreshTokenExpirationTimeSec(refreshTokenExpirationTimeSec);
            LogUtil.info("Expiration time in new refresh token has been extracted successfully(Refreshed):" + refreshTokenExpirationTimeSec, this);
        }
    }

    /**
     * 새로운 요청 객체의 어댑터 구현체를 이용하여 OIDC 세션 객체를 가져온다.<br>
     * @param sessionId 요청 객체의 세션 ID. JSESSIONID를 사용할 경우 request.getSession().getId()
     * @return OIDC 세션 객체. 없으면 Null을 리턴한다.
     */
    public OIDCSession getSessionBySessionID(final String sessionId){
        if (sessionId == null || sessionId.isEmpty()){
            return null;
        }
        return this.oidcSessionRegistry.getSessionBySessionId(sessionId);
    }
    /**
     * SID를 이용하여 OIDC 세션 객체를 가져온다.<br>
     * @param sid SID Claim 값
     * @return OIDC 세션 객체. 없으면 Null을 리턴한다.
     */
    public OIDCSession getSessionBySID(final String sid){
        if (sid == null || sid.isEmpty()){
            return null;
        }
        return this.oidcSessionRegistry.getSessionBySID(sid);
    }

    /**
     * Legacy Session 객체를 리턴
     * @param request 서블릿 요청 객체
     * @param response 서블릿 응답 객체
     * @return Legacy Session 객체.
     */
    public Object getLegacySession(HttpServletRequest request, HttpServletResponse response){
        return this.clientLegacySessionAdapter.getSession(request, response,null);
    }

    /**
     * 세션 갯수 확인
     * @return 세션 갯수
     */
    public int getSessionCount(){
        return this.oidcSessionRegistry.getSessionCount();
    }
}

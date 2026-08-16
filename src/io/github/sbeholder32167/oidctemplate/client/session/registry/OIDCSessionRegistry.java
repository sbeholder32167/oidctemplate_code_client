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
package io.github.sbeholder32167.oidctemplate.client.session.registry;

import io.github.sbeholder32167.oidctemplate.client.tokens.OIDCTokens;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSession;
import io.github.sbeholder32167.oidctemplate.client.session.repository.OIDCSessionRepository;
import io.github.sbeholder32167.oidctemplate.exception.OIDCException;
import io.github.sbeholder32167.oidctemplate.exception.OIDCExceptionEnum;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;

/**
 * OIDC Session Registry 추상 Class.<br>
 *
 * <p>OIDC Session의 중복 관리를 담당하며,<br>
 * 내부에 {@link OIDCSessionRepository}를 주입받고 동작한다.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-07-16
 */
public abstract class OIDCSessionRegistry {
    protected OIDCSessionRepository oidcSessionRepository;
    protected OIDCSessionRegistry(OIDCSessionRepository oidcSessionRepository){
        this.oidcSessionRepository = oidcSessionRepository;
    }

    /**
     * 세션 인덱스 등록<br>인덱스는 추후 중복 검사를 위해 사용
     * @param sid SID Claim 값
     * @param duplicateCheckKey 중복 확인 키.<br> 주로 사용자 ID 등의 식별자를 지정한다.<br>OIDC Tokens에 정의됨
     * @param sessionId 요청 객체의 세션 ID. JSESSIONID를 사용할 경우 request.getSession().getId()
     * @param tokens OIDCTokens 인증 객체.
     * @param timeoutSec OIDC 세션 Timeout (초).
     * @param accessTokenExpirationTimeSec Access Token 만료 시각(초)
     * @param refreshTokenExpirationTimeSec Refresh Token 만료 시각(초)
     */
    public abstract void register(final String sid, final Object duplicateCheckKey,
                                  final String sessionId, OIDCTokens tokens,
                                  final int timeoutSec,
                                  long accessTokenExpirationTimeSec,
                                  long refreshTokenExpirationTimeSec);
    /**
     * 전체 세션(인덱스) 갯수 리턴
     * @return 전체 세션(인덱스) 갯수
     */
    public abstract int getSessionCount();

    /**
     * WAS 세션 ID 이용하여 세션 내 인증 객체를 가져온다.<br>
     * @param sessionId 요청 객체의 세션 ID. JSESSIONID를 사용할 경우 request.getSession().getId()
     * @return 세션 객체. 없으면 Null을 리턴한다.
     */
    public OIDCSession getSessionBySessionId(final String sessionId){
        return this.oidcSessionRepository.getSessionBySessionId(sessionId);
    }
    /**
     * SID를 이용하여 세션 내 인증 객체를 가져온다.<br>
     * @param sid SID Claim 값
     * @return 세션 객체. 없으면 Null을 리턴한다.
     */
    public OIDCSession getSessionBySID(final String sid){
        return this.oidcSessionRepository.getSessionBySID(sid);
    }

    /**
     * 주어진 SID를 가진 세션을 만료시킨다<br>한개의 세션만 만료된다<br>
     * @param sid SID Claim 값
     */
    public abstract void invalidateSession(final String sid, final String sessionId, boolean isNow);
    /**
     * 주어진 중복 확인 키에 해당하는 SID를 가진 세션을 모두 만료시킨다.<br>
     * @param duplicateCheckKey OIDCToken의 중복 확인 키.<br> 주로 사용자 ID 등의 식별자를 지정한다.
     */
    public abstract void invalidateSession(final Object duplicateCheckKey);
    /**
     * 주어진 중복 확인 키에 해당하는 SID 세션 개수를 가져온다.
     * @param duplicateCheckKey OIDCToken의 중복 확인 키.<br> 주로 사용자 ID 등의 식별자를 지정한다.
     * @return SID 세션 개수
     */
    public abstract int getDuplicatedSessionCount(final Object duplicateCheckKey);

    /**
     * OIDC 세션의 Timeout을 확인.<br>
     * Timeout일 경우 만료시키고, Timeout이 되지 않았을 경우 연장시킨다<br>
     * @param oidcSession OIDC Session 객체.
     * @throws OIDCException OIDC Session이 Timeout일 경우 던져진다.
     */
    public void checkSessionTimeout(final OIDCSession oidcSession, final int timeoutSec) throws OIDCException {
        final long currentTimeSec = System.currentTimeMillis() / 1000;
        LogUtil.info("Seconds after last accessed : " + (currentTimeSec - oidcSession.getLastAccessedTime()), this);
        if (currentTimeSec - oidcSession.getLastAccessedTime() > timeoutSec){
            //-- OIDC session timeout.
            LogUtil.info("OIDC Session timeout : " + currentTimeSec + "-" + oidcSession.getLastAccessedTime(), this);
            this.invalidateSession(oidcSession.getSid(), oidcSession.getSessionId(), false);
            throw new OIDCException(OIDCExceptionEnum.OIDC_SESSION_TIMED_OUT, "OIDC Session Timed out.");
        }
        oidcSession.setLastAccessedTime(currentTimeSec);
        this.oidcSessionRepository.saveSession(oidcSession);
        LogUtil.info("OIDC Session Extended : [" + oidcSession.getSid() + "] " + currentTimeSec, this);
    }
}

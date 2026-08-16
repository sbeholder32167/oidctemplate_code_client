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
package io.github.sbeholder32167.oidctemplate.client.session.repository;

import io.github.sbeholder32167.oidctemplate.exception.OIDCException;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSession;

import java.util.Collection;

/**
 * OIDC Session Repository 추상 Class.<br>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-07-16
 */
public abstract class OIDCSessionRepository {

    /**
     * OIDC 세션을 저장소에 저장
     * @param oidcSession OIDC Session 객체.
     */
    public abstract void saveSession(OIDCSession oidcSession);

    /**
     * 세션 저장소 만료 처리<br>
     * 세션 저장소 구현체 만료처리 메서드.
     * @param sid SID Claim 값
     * @param sessionId 요청 객체의 세션 ID. JSESSIONID를 사용할 경우 request.getSession().getId(). Nullable
     * @param isNow 즉시 적용 여부를 설정. true일 경우 바로 OIDC 세션을 삭제, false일 경우 lazy 삭제하도록 구현
     */
    public abstract void expireSession(final String sid, final String sessionId, boolean isNow);

    /**
     * WAS 세션 ID 이용하여 세션 내 인증 객체를 가져온다.<br>
     * @param sessionId 요청 객체의 세션 ID. JSESSIONID를 사용할 경우 request.getSession().getId()
     * @return 세션 객체. 없으면 Null을 리턴한다.
     */
    public abstract OIDCSession getSessionBySessionId(final String sessionId);
    /**
     * SID를 이용하여 세션 내 인증 객체를 가져온다.<br>
     * @param sid SID Claim 값
     * @return 세션 객체. 없으면 Null을 리턴한다.
     */
    public abstract OIDCSession getSessionBySID(final String sid);
}

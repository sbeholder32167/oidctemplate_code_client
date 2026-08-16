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
package io.github.sbeholder32167.oidctemplate.client.session.repository.impl;

import io.github.sbeholder32167.oidctemplate.client.session.OIDCSession;
import io.github.sbeholder32167.oidctemplate.client.session.repository.OIDCSessionRepository;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Local Map Session Repository 구현 Class.<br>
 *
 * <p>Local Map을 OIDC Session Repository로 사용하는 구현체 예제 Class.<br>
 * 이 구현체는 오로지 OIDC Session만을 저장한다.<br>
 * 단일 On-Premise 서버에서만 사용.<br>
 * Default 구현체이며, 필요에 따라 커스터마이징 권장.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-07-16
 */
//-- XML Bean 등록
public class LocalMapSessionRepository extends OIDCSessionRepository {
    //-- SID (IDP Session ID) , OIDCSession Map.
    private final Map<String, OIDCSession> sessionMap = new ConcurrentHashMap<>();
    //-- WAS Session ID , SID(IDP Session ID) Map to use Request.getSession().getId()
    private final Map<String, String> sessionIdxMap = new ConcurrentHashMap<>();

    @Override
    public void saveSession(OIDCSession oidcSession) {
        this.sessionMap.put(oidcSession.getSid(), oidcSession);
        this.sessionIdxMap.put(oidcSession.getSessionId(), oidcSession.getSid());
    }

    @Override
    public void expireSession(String sid, String sessionId, boolean isNow) {
        OIDCSession sObj = this.sessionMap.get(sid);
        if (sObj == null){
            LogUtil.error("Not found OIDC Session Object: " + sessionId, this);
            return;
        }
        //-- Back Channel Logout 적극 권장.
        if (isNow){
            //-- 주의 : WAS Session은 삭제하지 않음
            String wasSessionId = (sessionId != null) ? sessionId : sObj.getSessionId();
            if (wasSessionId != null) {
                String mappedSid = this.sessionIdxMap.get(wasSessionId);
                if (sid.equals(mappedSid)) {
                    this.sessionIdxMap.remove(wasSessionId);
                } else {
                    LogUtil.error("Not equal SID(" + sid + ") <> Session ID(" + wasSessionId + ")", this);
                }
            }
            this.sessionMap.remove(sid);
        }else {
            //-- Interceptor에서 삭제해주도록 처리.
            //-- WAS Session까지 모두 삭제하려면 늦은 삭제가 더 안정적.
            sObj.setExpired(true);
            this.sessionMap.put(sid, sObj);
        }
    }

    @Override
    public OIDCSession getSessionBySessionId(String sessionId) {
        String sid = this.sessionIdxMap.get(sessionId);
        if (sid == null || sid.isEmpty()){
            return null;
        }
        return this.sessionMap.get(sid);
    }

    @Override
    public OIDCSession getSessionBySID(String sid) {
        return this.sessionMap.get(sid);
    }
}

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
package io.github.sbeholder32167.oidctemplate.client.session.registry.impl;

import io.github.sbeholder32167.oidctemplate.client.tokens.OIDCTokens;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSession;
import io.github.sbeholder32167.oidctemplate.client.session.registry.OIDCSessionRegistry;
import io.github.sbeholder32167.oidctemplate.client.session.repository.OIDCSessionRepository;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Local Map Session Registry 구현 Class.<br>
 *
 * <p>Local Map을 OIDC Session Index Registry로 사용하는 구현체<br>
 * 단일 On-Premise 서버에서만 사용할 것.<br>
 * Default 구현체이며 필요에 따라 커스터마이징 권장.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-07-16
 */
//-- XML Bean 등록
public class LocalMapSessionRegistry extends OIDCSessionRegistry {
    //-- Session Duplicate Check Key , SID(IDP Session ID) to check session duplicate.
    private final Map<Object, List<String>> duplicateCheckMap = new ConcurrentHashMap<>();
    //-- SID(IDP Session ID), Session Duplicate Check Key to check session duplicate.(Index Map)
    private final Map<String, Object> duplicateCheckIdx = new ConcurrentHashMap<>();

    public LocalMapSessionRegistry(OIDCSessionRepository oidcSessionRepository){
        super(oidcSessionRepository);
    }

    @Override
    public void register(final String sid, final Object duplicateCheckKey,
                         final String sessionId, OIDCTokens tokens,
                         final int timeoutSec,
                         long accessTokenExpirationTimeSec,
                         long refreshTokenExpirationTimeSec) {
        //-- to check duplicate session.
        List<String> sLst = this.duplicateCheckMap.get(duplicateCheckKey);
        if (sLst == null){
            sLst = new CopyOnWriteArrayList<String>();
        }
        sLst.add(sid);
        this.duplicateCheckMap.put(duplicateCheckKey, sLst);
        this.duplicateCheckIdx.put(sid, duplicateCheckKey);
        LogUtil.info("Current D-Map Size:" + this.duplicateCheckMap.size() + "/" + this.duplicateCheckIdx.size(), this);

        //-- save session.
        OIDCSession sObj = new OIDCSession(sid, sessionId, tokens, accessTokenExpirationTimeSec,refreshTokenExpirationTimeSec);
        this.oidcSessionRepository.saveSession(sObj);
    }

    @Override
    public int getSessionCount() {
        return this.duplicateCheckIdx.size();
    }

    @Override
    public void invalidateSession(final String sid, final String sessionId, boolean isNow){
        //-- Update session duplicate map.
        Object dKey = this.duplicateCheckIdx.get(sid);
        if (dKey != null){
            List<String> sLst = this.duplicateCheckMap.get(dKey);
            if (sLst != null){
                sLst.remove(sid);
                if (sLst.isEmpty()){
                    this.duplicateCheckMap.remove(dKey);
                }else{
                    this.duplicateCheckMap.put(dKey, sLst);
                }
            }else{
                LogUtil.info("Session id duplicate info Not found.", this);
            }
        }else{
            LogUtil.info("Session duplicate info Not found.", this);
        }
        this.duplicateCheckIdx.remove(sid);
        LogUtil.info("D-Map Removed. Current D-Map Size:" + this.duplicateCheckMap.size() + "/" + this.duplicateCheckIdx.size(), this);
        this.oidcSessionRepository.expireSession(sid, sessionId, isNow);
    }
    @Override
    public void invalidateSession(Object duplicateCheckKey) {
        List<String> sLst = this.duplicateCheckMap.get(duplicateCheckKey);
        if (sLst != null && !sLst.isEmpty()){
            for (String duplicatedSid : sLst){
                //-- Repository Lazy Invalidation.
                this.oidcSessionRepository.expireSession(duplicatedSid, null, false);
                this.duplicateCheckIdx.remove(duplicatedSid);
            }
        }
        this.duplicateCheckMap.remove(duplicateCheckKey);
    }

    @Override
    public int getDuplicatedSessionCount(Object duplicateCheckKey) {
        List<String> sLst = this.duplicateCheckMap.get(duplicateCheckKey);
        if (sLst != null){
            return sLst.size();
        }else{
            return 0;
        }
    }
}

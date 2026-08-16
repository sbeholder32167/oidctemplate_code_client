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
package io.github.sbeholder32167.oidctemplate.client.session.storage.impl;

import io.github.sbeholder32167.oidctemplate.exception.OIDCException;
import io.github.sbeholder32167.oidctemplate.exception.OIDCExceptionEnum;
import io.github.sbeholder32167.oidctemplate.client.session.storage.OIDCAuthParameterStorage;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Local Memory 인증 Parameter 임시 저장소 구현 Class.<br>
 *
 * <p>Authentication Code Flow 중 사용되는 Request Parameter를 Memory Map에 임시로 저장하는 Logic이 구현된 Class.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-30
 */
//-- XML Bean 등록
public class LocalMemoryAuthParameterStorage implements OIDCAuthParameterStorage {
    //-- use in authentication code flow only.
    private final Map<String, Map<String, Object>> requestParamMap = new ConcurrentHashMap<>();

    @Override
    public void setRequestParameter(final String key, final String value, final String sessionId) throws OIDCException {
        Map<String, Object> paramMap = this.requestParamMap.get(sessionId);
        if (paramMap == null){
            paramMap = new HashMap<String, Object>();
        }
        paramMap.put(key, value);
        this.requestParamMap.put(sessionId, paramMap);
    }
    @Override
    public String getRequestParameterValue(final String key, boolean remove, final String sessionId) throws OIDCException {
        Map<String, Object> paramMap = this.requestParamMap.get(sessionId);
        if (paramMap != null){
            Object tObj = paramMap.get(key);
            if (tObj == null){
                return null;
            }else{
                String result = String.valueOf(tObj);
                if (remove){
                    paramMap.remove(key);
                }
                return result;
            }
        }else{
            throw new OIDCException(OIDCExceptionEnum.IDP_AUTH_REDIRECT, "No parameter map in the session.");
        }
    }

    @Override
    public Object getRequestParameterAdapter(final String sessionId) {
        return this.requestParamMap.get(sessionId);
    }

    @Override
    public void removeRequestParameterAdapter(final String sessionId) {
        Map<String, Object> paramMap = this.requestParamMap.get(sessionId);
        if (paramMap != null){
            this.requestParamMap.remove(sessionId);
        }
    }
}

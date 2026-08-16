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
package io.github.sbeholder32167.oidctemplate.client.session.storage;

import io.github.sbeholder32167.oidctemplate.exception.OIDCException;
import io.github.sbeholder32167.oidctemplate.client.provider.AbstractOIDCProvider;

/**
 * OIDC 인증 Parameter 임시 저장소 Interface.<br>
 *
 * <p>Authentication Code Flow 중 사용되는 Request Parameter 임시 저장소 Interface.<br>
 * OIDC Flow 중 State, Session State, PKCE Verifier 등의 값을 Client에서 유지시 사용<br>
 * 주 사용처는 {@link AbstractOIDCProvider }이다.</p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-30
 */
public interface OIDCAuthParameterStorage {
    /**
     * 요청 파라미터를 임시로 저장<br>
     * Redirect URI를 통해 Code로 유입된 후 까지 유지되어 있으면 된다.
     * @param key state, session_state, pkce_verifier ...
     * @param value 값
     * @param sessionId 요청 객체의 세션 ID. JSESSIONID를 사용할 경우 request.getSession().getId()
     */
    void setRequestParameter(final String key, final String value, final String sessionId) throws OIDCException;
    /**
     * 요청 파라미터를 가져온다<br>
     * @param key state, session_state, pkce_verifier ...
     * @param remove 삭제 여부. true이면 가져옴과 동시에 삭제.
     * @param sessionId 요청 객체의 세션 ID. JSESSIONID를 사용할 경우 request.getSession().getId()
     * @return 값
     * @throws OIDCException 주어진 Session ID에 해당된 객체 자체가 없다면 발생
     */
    String getRequestParameterValue(final String key, final boolean remove, final String sessionId) throws OIDCException;
    /**
     * 요청 파라미터를 담은 객체를 가져온다.<br>
     * OIDC Session Interceptor에서 사용한다<br>
     * @param sessionId 요청 객체의 세션 ID. JSESSIONID를 사용할 경우 request.getSession().getId()
     * @return key, value를 가진 저장 객체가 리턴된다. 없으면 null을 리턴.
     */
    Object getRequestParameterAdapter(final String sessionId);
    /**
     * 요청 파라미터 및 어댑터 전체를 삭제
     * @param sessionId 요청 객체의 세션 ID. JSESSIONID를 사용할 경우 request.getSession().getId()
     */
    void removeRequestParameterAdapter(final String sessionId);
}

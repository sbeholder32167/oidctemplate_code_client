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
package io.github.sbeholder32167.oidctemplate.adapter;

import io.github.sbeholder32167.oidctemplate.client.session.OIDCSessionManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Client Legacy Session Adapter.<br>
 *
 * <p>Controller에서 Client의 레거시 세션 처리 시 사용<br>
 * Client의 WAS Session을 고려한 Customizing이 필요한 인터페이스
 * Client의 자체 세션 관리에 연동할 때 사용한다<br><br>
 * ※.주의 <br>
 * {@link OIDCSessionManager}는 자체 OIDC Session을 관리하는 인터페이스이며,<br>
 * 그 인터페이스는 OIDC의 SID에 따른 세션과 토큰값을 관리하는 인터페이스이다. Legacy Client와 무관하다.<br>
 * 그에 비해, 이 인터페이스는 Legacy Client Session과의 연동을 위한 인터페이스이다.</p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-06-09
 */
public interface ClientLegacySessionAdapter {
    /**
     * 세션을 가져오도록 처리
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @param param 관련 parameter. Nullable.
     * @return OIDCTokens등의 세션 객체
     */
    Object getSession(HttpServletRequest request, HttpServletResponse response, Object param);

    /**
     * 세션 저장<br>
     * Spring Security를 사용하고 Filter / Provider를 이용하고 있다면, 굳이 이 Method를 실행시켜줄 필요는 없다.<br>
     * Provider에서 리턴된 인증 객체를 자동으로 세션에 등록시켜주기 때문<br>
     * 실제로 OIDCAuthenticationProvider와 OIDCLoginFilter에서는 이 메서드를 호출하지 않는다.
     * (AbstractAuthenticationProcessingFilter의 doFilter에서 세션을 저장)
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @param legacySessionObj Legacy Session Object. AuthConvertAdapter에서 생성된 객체.
     * @param created 세션을 생성할지 갱신할지를 정하는 flag. 새로 생성된 세션이라면 true로 지정.
     * @param param 관련 parameter. Nullable.
     */
    void setSession(HttpServletRequest request, HttpServletResponse response, Object legacySessionObj, boolean created, Object param);

    /**
     * 세션 삭제 처리
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @param param 관련 parameter. Nullable.
     */
    void invalidateSession(HttpServletRequest request, HttpServletResponse response, Object param);
}

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

import io.github.sbeholder32167.oidctemplate.exception.OIDCException;
import io.github.sbeholder32167.oidctemplate.client.tokens.OIDCTokens;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 인증 후 후처리 Adapter Interface<br>
 *
 * <p>인증 후 후처리 Logic을 구현한다<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-06-07
 */
public interface ClientLoginAdapter {
    /**
     * OIDC 인증 후 후처리<br>인증된 사용자가 DB에 있는지 확인 및 저장 등의 추가 Logic 구현<br>
     * 반드시 마지막은 response.sendRedirect로 구현할 것.<br>
     * OIDCAuthSuccessHandler에서 호출된다<br>
     * @param request 서블릿 요청 객체
     * @param response 서블릿 응답 객체
     * @param oidcTokens OIDC Session 내부의 인증 객체
     * @param legacySessionObj Legacy Session Object. Auth Convert Adapter에서 생성된 구현체
     */
    void doJobPostLogin(HttpServletRequest request, HttpServletResponse response, OIDCTokens oidcTokens, Object legacySessionObj);
    /**
     * OIDC 인증 실패 시 후처리<br> IDP 인증은 성공했으나, Parameter 부족 또는 Client 세션 중복등으로 인하여 실패한 경우 호출된다.<br>
     * 반드시 마지막은 response.sendRedirect로 구현할 것.<br>
     * OIDCAuthSuccessHandler에서 호출된다
     * @param request 서블릿 요청 객체
     * @param response 서블릿 응답 객체
     * @param cause 로그인 실패 원인 OIDCException. Nullable
     */
    void doJobFailedLogin(HttpServletRequest request, HttpServletResponse response, OIDCException cause);
}

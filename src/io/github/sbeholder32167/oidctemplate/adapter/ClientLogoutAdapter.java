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

import io.github.sbeholder32167.oidctemplate.client.tokens.OIDCTokens;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 로그아웃 후 후처리 Adapter Interface<br>
 *
 * <p>로그아웃 이후 동작을 정의하기 위한 Customizing Interface.<br>
 * 구현체는 XML에 Bean으로 등록한 후, Autowired / Resource 등으로 Controller에서 주입받아 사용<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-06-07
 */
public interface ClientLogoutAdapter {
    /**
     * Logout 동작 전 처리할 일을 구현.<br>
     * Logout Request의 경우 IDP의 BackChannel로 진행될 경우가 있으므로 인증된 사용자의 요청이 아닐수 있다.<br>
     * 즉, Spring Security의 Context Holder가 항상 유효하지는 않다. 그래서 레거시 세션 핸들링은 제외함.<br>
     * 화면 이동이 없는 로직이므로, response.sendRedirect를 사용하지 말것.<br>
     * @param request 서블릿 요청 객체
     * @param response 서블릿 응답 객체
     * @param oidcTokens 인증 객체
     */
    void doJobBeforeLogout(HttpServletRequest request, HttpServletResponse response, OIDCTokens oidcTokens);
    /**
     * Logout 성공 후 처리할 일을 구현.<br>
     * 세션이 만료되었으므로, Request는 의미가 없다.<br>
     * 화면 이동이 없는 로직이므로, response.sendRedirect를 사용하지 말것.
     * @param response 서블릿 응답 객체
     * @param oidcTokens 인증 객체
     */
    void doJobPostLogout(HttpServletResponse response, OIDCTokens oidcTokens);
}

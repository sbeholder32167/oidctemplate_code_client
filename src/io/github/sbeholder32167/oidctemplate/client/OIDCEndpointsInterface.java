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
package io.github.sbeholder32167.oidctemplate.client;

import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * OIDC Endpoint를 정의한 Interface.<br>
 *
 * <p>OIDC의 동작에 필요한 기본 Endpoint 정의 Interface.<br>
 * Authentication Code Flow 인증과 로그아웃 Endpoint 구현 누락 방지 외 큰 의미는 없음.<br>
 * 어차피 Controller Template에만 사용되었다.</p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-07-03
 */
public interface OIDCEndpointsInterface {
    /**
     * OIDC 인증 페이지로 Redirect한다.
     * @param request 서블릿 요청 객체.
     * @exception IOException Page redirect에 따른 Exception
     */
    void redirectOIDCAuthentication(HttpServletRequest request, HttpServletResponse response) throws IOException;

    /**
     * OIDC 인증을 진행.<br> Redirect_uri의 Endpoint.
     * @param request 서블릿 요청 객체.
     * @param response 서블릿 응답 객체.
     * @exception IOException Page redirect에 따른 Exception
     */
    void processOidcAuth(HttpServletRequest request, HttpServletResponse response) throws IOException;

    /**
     * Front Channel logout을 위한 Endpoint.<br>
     * 이 endpoint의 사용은 권장하지 않는다<br>
     * Edge에서 쿠키를 전달하지 않는 문제를 확인함.<br> 이로 인하여 사용자의 사용중 세션인지를 확인할 수가 없다.
     * Back Channel logout 사용 권장.
     * @param request 서블릿 요청 객체.
     * @param response 서블릿 응답 객체.
     * @param sid SID Claim 값.
     * @param iss Issuer Claim 값.
     */
    void handleFrontChannelLogout(HttpServletRequest request, HttpServletResponse response,
                                  @RequestParam("sid") String sid, @RequestParam(value = "iss", required = false) String iss) throws IOException;
    /**
     * Back Channel logout을 위한 Endpoint.<br>
     * 이 endpoint는 CSRF 보호를 하면 안된다.<br> IDP의 Logout 요청이 CSRF Token이 없이 여기로 진입된다.
     * @param request 서블릿 요청 객체.
     * @param response 서블릿 응답 객체.
     */
    void handleBackChannelLogout(HttpServletRequest request, HttpServletResponse response) throws IOException;
    /**
     * 사용자가 직접 Logout 할 경우 사용되는 엔드포인트<br> logout 버튼을 명시적으로 클릭할 경우 이 Endpoint를 사용.
     * @param request 서블릿 요청 객체
     * @param response 서블릿 응답 객체
     */
    void doLogoutManually(HttpServletRequest request, HttpServletResponse response) throws IOException;
}

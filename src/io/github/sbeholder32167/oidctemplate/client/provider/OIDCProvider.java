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
package io.github.sbeholder32167.oidctemplate.client.provider;

import io.github.sbeholder32167.oidctemplate.adapter.ClientLogoutAdapter;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSessionManager;
import io.github.sbeholder32167.oidctemplate.exception.OIDCException;
import io.github.sbeholder32167.oidctemplate.jwks.exception.JWKSException;
import io.github.sbeholder32167.oidctemplate.client.OIDCDataTransferObject;
import io.github.sbeholder32167.oidctemplate.client.OIDCTokenTransferObject;
import io.github.sbeholder32167.oidctemplate.client.exception.RBACException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * OIDC 인증 제공자 Interface.<br>
 *
 * <p>OIDC 인증에 필요한 동작 및 각종 Parameter와 Logic이 정의된 Interface.<br>
 * IDP에 따라 따로 구현되어야 한다.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-06-28
 * @see AbstractOIDCProvider
 */
public interface OIDCProvider {
    /**
     * IDP 인증 페이지로의 Redirect를 위한 URL을 생성하고 그 페이지로 Redirect한다.<br>
     * OAuth 2.0 Standard flow의 시작점.<br>
     * Request Parameter (state, PKCE) 를 생성해야 하는 위치이다.<br>
     * @param request 서블릿 요청 객체
     * @param response 서블릿 응답 객체. Redirect에 활용.
     * @param redirectUri Login Filter에 정의된 Redirect URL.
     * @throws OIDCException URL Encoding Exception
     */
    void redirectIDPAuthPage(HttpServletRequest request, HttpServletResponse response, final String redirectUri) throws OIDCException, IOException;

    /**
     * Parameter parsing. DTO 생성.<br> IDP 인증 후 Redirect URL로 진입할 경우 이용된다.<br>
     * Request Parameter (state, PKCE) 를 청소하기 좋은 위치이다.<br>
     * @param request 서블릿 요청 객체
     * @return Code, Code Verifier, state, Session State, Scope가 포함된 객체.
     * @throws OIDCException Parameter / State check failed.
     */
    OIDCDataTransferObject checkParameters(HttpServletRequest request) throws OIDCException;

    /**
     * IDP에서 Token을 가져온다
     * @param dto Code, Code Verifier, state, Session State, Scope가 포함된 객체.
     * @param redirectUri Redirect Uri
     * @return Token 객체.(ID Token, Access Token, Refresh Token)
     * @throws OIDCException Token을 받지 못했거나 누락된 경우 던져진다
     */
    OIDCTokenTransferObject acquireTokens(OIDCDataTransferObject dto, final String redirectUri) throws OIDCException;

    /**
     * 토큰을 갱신한다
     * @param refreshToken Refresh Token
     * @return Token 객체.(ID Token, Access Token, Refresh Token)
     * @throws OIDCException Token을 받지 못했거나 누락된 경우 던져진다
     */
    OIDCTokenTransferObject refreshTokens(final String refreshToken) throws OIDCException;

    /**
     * JWKS 토큰 검증
     * @param token ID, Access, Logout Token
     * @param checkAud AUD Claim(Client ID) 검증 여부. Id Token만 true로 지정. Access Token은 false로 지정.
     * @throws OIDCException 검증이 실패하면 발생하며, 내부적으로 {@link JWKSException}이 발생한다
     */
    void verifyToken(final String token, final boolean checkAud) throws OIDCException;

    /**
     * Access Token의 만료시간을 추출<br>
     * OIDCSession Storage의 register 메서드에서 사용된다.<br>
     * @param accessToken OIDCTokens 객체. 내부 Access Token이 있어야 한다.
     * @return Access Token 만료시각(초)
     * @throws RBACException Access Token이 null 또는 빈칸이거나 파싱 실패일 경우 던져진다
     */
    long extractAccessTokenExpirationTime(final String accessToken) throws RBACException;
    /**
     * Refresh Token의 만료시간을 추출<br>
     * OIDCSession Storage의 register 메서드에서 사용된다.<br>
     * @param refreshToken OIDCTokens 객체. 내부 Refresh Token이 있어야 한다.
     * @return Refresh Token 만료시각(초)
     * @throws RBACException Refresh Token이 null 또는 빈칸이거나 파싱 실패일 경우 던져진다
     */
    long extractRefreshTokenExpirationTime(final String refreshToken) throws RBACException;

    /**
     * Outbound IDP Logout을 수행한다.<br>
     * @param request 서블릿 요청 객체
     * @param response 서블릿 응답 객체
     * @param oidcSessionManager OIDC 세션 관리자. 내부 OIDC Logout을 수행하기 위해 필요.
     * @param clientLogoutAdapter Client Logout Adapter. 내부 OIDC Logout 전/후 처리를 위해 필요.
     * @throws OIDCException OIDC 세션에 ID Token이 없을 경우를 포함한 OIDC 관련 예외 발생 시 던져진다.
     * @throws IOException Redirect 동작이 존재할 경우, 실패 시 발생
     */
    void doOutboundIDPLogout(HttpServletRequest request, HttpServletResponse response,
                             OIDCSessionManager oidcSessionManager, ClientLogoutAdapter clientLogoutAdapter) throws OIDCException, IOException;

    /**
     * Inbound IDP Logout에 대응하여 수행.<br>
     * @param request 서블릿 요청 객체
     * @param response 서블릿 응답 객체
     * @param oidcSessionManager OIDC 세션 관리자. 내부 OIDC Logout을 수행하기 위해 필요.
     * @param clientLogoutAdapter Client Logout Adapter. 내부 OIDC Logout 전/후 처리를 위해 필요.
     * @throws OIDCException Logout Token 검증 실패 또는 각종 로그아웃 관련 예외 발생 시 던져진다
     */
    void doInboundIDPLogout(HttpServletRequest request, HttpServletResponse response,
                            OIDCSessionManager oidcSessionManager, ClientLogoutAdapter clientLogoutAdapter) throws OIDCException;
}

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

import org.springframework.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * AUTHZ 동작 중 예외처리 Interface.<br>
 *
 * <p>AUTHZ 인가 처리 도중 예외 처리 Interface.<br>
 * AUTHZ Interceptor에서의 예외 발생에 따른 동작을 구현하여 Bean으로 적용 필요<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-06-17
 */
public interface ClientAuthzExceptionAdapter {
    /**
     * 인가 실패로 인해 접근이 거부될 경우, Json 리턴 Logic의 정의 <br>
     * JSON 방식으로 리턴되는 엔드포인트의 인증 실패 또는 접근 거부 시 메시지를 생성 <br>
     * @param status HttpStatus
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @param resourceName 인가 Resource 명
     * @param scopes 인가 Scope 배열
     */
    void handleBlockJson(HttpStatus status, HttpServletRequest request, HttpServletResponse response,
                         final String resourceName, String[] scopes);

    /**
     * 인가 실패로 인해 접근이 거부될 경우, 그에 따른 동작을 정의 <br>
     * JSON 방식으로 리턴되지 않는 엔드포인트의 접근 거부 시 동작 <br>
     * Redirect 또는 예외 처리 등 <br>
     * @param status Http Status
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @param resourceName 인가 Resource 명
     * @param scopes 인가 Scope 배열
     */
    void handleBlockHtml(HttpStatus status, HttpServletRequest request, HttpServletResponse response,
                         final String resourceName, String[] scopes);
}

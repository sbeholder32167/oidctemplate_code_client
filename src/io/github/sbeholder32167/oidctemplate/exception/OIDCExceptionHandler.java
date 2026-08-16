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
package io.github.sbeholder32167.oidctemplate.exception;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OIDC 예외 처리 Handler Adapter Interface.<br>
 *
 * <p>OIDC 인증 도중 발생하는 예외 처리를 정의한 Interface.<br>
 * 각 Client에 맞게 구현되어야 한다.<br>
 * 구현체는 Bean으로 등록.</p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-22
 */
public interface OIDCExceptionHandler {
    /**
     * 예외 처리
     * @param step 예외 발생 단계.
     * @param e 예외 객체. 단, step과 다를 수 있음.
     * @param request 서블릿 요청 객체.
     * @param response 서블릿 응답 객체. Redirect를 위한 Parameter.
     */
    void handleException(OIDCExceptionEnum step, Exception e, HttpServletRequest request, HttpServletResponse response);
}

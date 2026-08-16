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
 * ABAC 동작 중 예외처리 Interface.<br>
 *
 * <p>ABAC 인가 처리 도중 예외 처리 Interface.<br>
 * ABAC Interceptor에서의 예외 발생에 따른 동작을 구현하여 Bean으로 적용 필요<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-06-17
 */
public interface ClientAuthzExceptionAdapter {
    /**
     * Json 형식으로 인증이 거부되거나 접근이 거부될 경우의 Json Format을 정의 <br>
     * JSON 방식으로 리턴되는 엔드포인트의 인증 실패 또는 접근 거부 시 메시지를 생성 <br>
     * @param status HttpStatus
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @return Json Message
     */
    String generateJsonMessage(HttpStatus status, HttpServletRequest request,
                               HttpServletResponse response);

    /**
     * 인증 실패 또는 접근 거부에 따른 동작을 정의 <br>
     * JSON 방식으로 리턴되지 않는 엔드포인트의 접근 거부 시 동작 <br>
     * Redirect 또는 예외 처리 등 <br>
     * @param status Http Status
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     */
    void doPostAuthException(HttpStatus status, HttpServletRequest request,
                             HttpServletResponse response);
}

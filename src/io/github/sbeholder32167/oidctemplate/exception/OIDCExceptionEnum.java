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

/**
 * OIDC 예외 Class에서 사용되는 예외발생 위치 목록.<br>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-22
*/
public enum OIDCExceptionEnum {
    RBAC,ABAC,
    IDP_AUTH_REDIRECT,
    CHECK_PARAMETERS,
    CHECK_STATE,
    NULL_CODE_DTO,
    NULL_TOKEN_RESPONSE,
    INSUFFICIENT_TOKEN,
    VERIFY_TOKEN,

    NULL_SESSION_ID,
    OIDC_SESSION_TIMED_OUT,
    NO_SESSION_ADAPTER,

    REFRESH_ACCESS_TOKEN,
    OIDC_SESSION_EXCEPTION,
    REQ_SESSION_EXCEPTION,
    OIDC_SESSION_DUPLICATE,

    IDP_LOGOUT_EXCEPTION,
    NULL_LOGOUT_TOKEN,
    INVALID_LOGOUT_TOKEN
}

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
package io.github.sbeholder32167.oidctemplate.client.exception;

/**
 * 인증 Code Flow 중 예외 정의<br>
 *
 * <p>인증 Code Flow 진행 중 발생하는 예외와 단계에 대해 정의.</p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-10-09
 */
public class AuthenticationCodeFlowException extends OIDCException {
    private final AuthenticationCodeFlowException.Step step;
    private final AuthenticationCodeFlowException.Cause expCause;
    public AuthenticationCodeFlowException(AuthenticationCodeFlowException.Step step,
                                           AuthenticationCodeFlowException.Cause expCause,
                                           String message) {
        super(OIDCException.Category.AUTH_CODE_FLOW, message);
        this.step = step;
        this.expCause = expCause;
    }
    public Step getStep(){
        return this.step;
    }
    public Cause getExpCause(){
        return this.expCause;
    }

    public enum Step{
        IDP_AUTH_REDIRECT,
        CHECK_PARAMETERS,
        CHECK_STATE,
        TOKEN_EXCHANGE,
        COMMON,
        LOGOUT,
    }
    public enum Cause{
        NULL_WAS_SESSION_ID,
        NO_PARAM_MAP,
        INSUFFICIENT,
        INVALID,
        NULL_VALUE,
        NO_OIDC_SESSION,
        NO_SID,
        REDIRECT,
        UNKNOWN
    }
}

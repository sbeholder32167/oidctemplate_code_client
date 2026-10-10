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
 * 인증 예외 정의<br>
 *
 * <p>인증 예외에 대해 정의한 예외이지만, 인증 Flow는 나타내지 않음.<br/>
 * 인증 실패에 대한 공통 예외.</p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-10-10
 */
public class OIDCAuthenticationException extends AuthenticationCodeFlowException {
    public OIDCAuthenticationException(String message) {
        super(Step.COMMON, Cause.UNKNOWN, message);
    }
}

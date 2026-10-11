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
 * Token 검증 예외 정의<br>
 *
 * <p>Token 검증 중 발생하는 예외와 원인에 대해 정의.</p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-10-07
 */
public class TokenVerifyException extends TokenProcessingException {
    private final TokenVerifyException.Cause expCause;
    public TokenVerifyException(TokenVerifyException.Cause exceptionCause, String message) {
        super(message);
        this.expCause = exceptionCause;
    }
    public Cause getExpCause(){
        return this.expCause;
    }

    public enum Cause{
        JWKS,
        DECODE_JWT,
        NO_CLAIM,
        INVALID_ISSUER,
        NULL_AUDIENCE,
        INVALID_AUDIENCE,
        NULL_NONCE,
        INVALID_NONCE,
        ALREADY_EXPIRED,
        INVALID_ISSUED,
        INVALID_NOT_BEFORE,
        INVALID_AUTHORIZED_PARTY,
        USER_INFO_QUERY_FAILED
    }
}

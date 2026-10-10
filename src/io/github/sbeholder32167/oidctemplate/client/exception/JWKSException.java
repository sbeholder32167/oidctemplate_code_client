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
 * JWKS 검증 관련 예외 Class.<br>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-26
 */
public class JWKSException extends OIDCException {
    public final JWKSException.Step step;
    public JWKSException(JWKSException.Step step, String message) {
        super(OIDCException.Category.JWKS,message);
        this.step = step;
    }
    public enum Step{
        DECODE_JWT,
        NULL_ALG,
        NO_ALG,
        NULL_JWKS_RESPONSE,
        FAILED_JWKS_RESPONSE,
        NO_KEYS,
        NO_CERTS,
        GEN_CERTS_ERR,
        EXT_CERTS_ERR,
        NOT_SUPPORTED_ALG,
        INVALID_SIG
    }
}

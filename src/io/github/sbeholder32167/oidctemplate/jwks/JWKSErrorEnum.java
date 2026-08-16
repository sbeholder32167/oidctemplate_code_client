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
package io.github.sbeholder32167.oidctemplate.jwks;

/**
 * JWKS 검증 시 예외 발생 위치 목록.<br>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-26
 */
public enum JWKSErrorEnum {
    DECODE_JWT(0),
    NULL_ALG(1),
    NO_ALG(2),
    NULL_AUDIENCE(10),
    INVALID_AUDIENCE(11),
    NULL_JWKS_RESPONSE(20),
    FAILED_JWKS_RESPONSE(21),
    NO_KEYS(30),
    NO_CERTS(40),
    GEN_CERTS_ERR(41),
    EXT_CERTS_ERR(42),
    NOT_SUPPORTED_ALG(50),
    INVALID_SIG(60);

    final int stepCd;
    JWKSErrorEnum(final int stepCd){
        this.stepCd = stepCd;
    }
}

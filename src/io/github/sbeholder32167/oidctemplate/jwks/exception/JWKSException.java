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
package io.github.sbeholder32167.oidctemplate.jwks.exception;

import io.github.sbeholder32167.oidctemplate.jwks.JWKSErrorEnum;
import io.github.sbeholder32167.oidctemplate.client.exception.RBACException;

/**
 * JWKS 검증 관련 예외 Class.<br>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-26
 */
public class JWKSException extends RBACException {
    public final JWKSErrorEnum step;
    public JWKSException(JWKSErrorEnum step, String message) {
        super(message);
        this.step = step;
    }
}

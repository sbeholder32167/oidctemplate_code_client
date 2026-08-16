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

import io.github.sbeholder32167.oidctemplate.exception.OIDCException;
import io.github.sbeholder32167.oidctemplate.exception.OIDCExceptionEnum;

/**
 * RBAC 동작 Exception class
 *
 * <p>RBAC 동작 관련 예외 Class</p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-22
 */
public class RBACException extends OIDCException {
    public RBACException(String message) {
        super(OIDCExceptionEnum.RBAC, message);
    }
}

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
package io.github.sbeholder32167.oidctemplate.client.session.duplicatepolicy;

import io.github.sbeholder32167.oidctemplate.client.exception.RBACException;
import io.github.sbeholder32167.oidctemplate.client.session.registry.OIDCSessionRegistry;

/**
 * OIDC 세션 중복 정의 Interface.<br>
 *
 * <p>OIDC 세션 중복 시 정책을 정의하는 Interface.<br>
 * </p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-07-09
 */
public interface OIDCSessionDuplicatePolicy {
    /**
     * 세션 중복 시 동작을 정의
     * @param duplicateCheckKey 중복 확인 키. OIDCTokens에 정의되어 있다.
     * @param sessionRegistry OIDC Session Registry
     * @throws RBACException Session 등록을 중단시키기 위해 사용됨
     */
    void onDuplicateOIDCSession(Object duplicateCheckKey, OIDCSessionRegistry sessionRegistry) throws RBACException;
}

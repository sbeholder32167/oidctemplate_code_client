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
package io.github.sbeholder32167.oidctemplate.client.session.duplicatepolicy.impl;

import io.github.sbeholder32167.oidctemplate.client.exception.RBACException;
import io.github.sbeholder32167.oidctemplate.client.session.duplicatepolicy.OIDCSessionDuplicatePolicy;
import io.github.sbeholder32167.oidctemplate.client.session.registry.OIDCSessionRegistry;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;

/**
 * 오직 한개의 세션만을 허용하고, 이전 세션은 만료시키는 정책 구현 Class.<br>
 *
 * <p>하나의 세션만을 통과시키고 같은 식별자의 다른 세션이 유입되면 그 세션으로 변경<br>
 * 동일한 식별자를 가진 다른 세션이 등록되면 그 세션으로 대체되고 기존 세션은 만료된다<br>
 * Default 구현체이며 필요시 커스터마이징 권장.<br></p>
 *
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-07-09
 */
//-- XML Bean 등록
public class OneAllowSessionDuplicatePolicy implements OIDCSessionDuplicatePolicy {
    @Override
    public void onDuplicateOIDCSession(Object duplicateCheckKey, OIDCSessionRegistry sessionRegistry) throws RBACException {
        LogUtil.info("Session Policy : One allow.", this);
        //-- Lazy Invalidate Exist Session.
        if (sessionRegistry.getDuplicatedSessionCount(duplicateCheckKey) > 0){
            sessionRegistry.invalidateSession(duplicateCheckKey);
        }
    }
}

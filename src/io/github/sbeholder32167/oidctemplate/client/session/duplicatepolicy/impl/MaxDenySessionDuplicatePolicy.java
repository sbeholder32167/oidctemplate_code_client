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
 * 정해진 최대 세션수까지만 세션 등록을 허용하는 세션 중복 정책 구현 Class.<br>
 *
 * <p>동일한 식별자를 가진 세션의 최대 수까지 허용하고, 그 이상의 동일 식별자 세션이 진입하면 등록을 거부한다<br>
 * Default 구현체이며 필요시 커스터마이징 권장.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-07-09
 */
//-- XML Bean 등록
public class MaxDenySessionDuplicatePolicy implements OIDCSessionDuplicatePolicy {
    /**
     * OIDC 세션 중복 시 최대 허용 갯수
     */
    private int maxSessionCnt = 10;
    public void setMaxSessionCnt(final int maxSessionCnt){
        this.maxSessionCnt = maxSessionCnt;
    }

    @Override
    public void onDuplicateOIDCSession(Object duplicateCheckKey, OIDCSessionRegistry sessionRegistry) throws RBACException {
        LogUtil.info("Session Policy : Maximum Deny. (Limit:" + this.maxSessionCnt + ")", this);
        if (this.maxSessionCnt <= sessionRegistry.getDuplicatedSessionCount(duplicateCheckKey)){
            throw new RBACException("Maximum Session duplicate count reached.");
        }
    }
}

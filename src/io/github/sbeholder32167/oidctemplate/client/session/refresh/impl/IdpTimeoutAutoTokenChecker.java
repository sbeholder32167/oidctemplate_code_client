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
package io.github.sbeholder32167.oidctemplate.client.session.refresh.impl;

import io.github.sbeholder32167.oidctemplate.client.session.OIDCSession;
import io.github.sbeholder32167.oidctemplate.client.session.refresh.OIDCAutoTokenChecker;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;

/**
 * IDP Timeout 기준 갱신 정책 구현체 Class.<br>
 *
 * <p>특이하게 IDP Timeout을 기준으로 Token Refresh 필요 여부를 판단<br>
 * IDP Timeout은 그냥 설정 값이다.<br>
 * IDP Session Timeout과 맞추도록 권장<br>
 * Default 구현체이며 필요시 커스터마이징하여 사용 권장.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-07-09
 */
//-- XML Bean 등록
public class IdpTimeoutAutoTokenChecker implements OIDCAutoTokenChecker {
    @Override
    public boolean needToRefreshTokens(OIDCSession oidcSession, int idpTimeoutSec, int skewSec) {
        LogUtil.info("check token expiration.", this);
        long currentTimeSec = System.currentTimeMillis() / 1000;
        return (oidcSession.getLatestIdptouchTimeSec() + idpTimeoutSec) - skewSec < currentTimeSec;
    }
}

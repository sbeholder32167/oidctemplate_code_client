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
package io.github.sbeholder32167.oidctemplate.client.session.refresh;

import io.github.sbeholder32167.oidctemplate.client.session.registry.impl.LocalMapSessionRegistry;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSession;

/**
 * 토큰 자동 갱신 정책 Interface.<br>
 *
 * <p>IDP로부터 받은 각종 Token들의 자동 갱신 정책을 정의하는 Interface.<br>
 * 자동 갱신 기능이 지원되지 않는 OIDC Session Registry를 사용한다면 구현할 필요는 없음.<br>
 * 사실상 {@link LocalMapSessionRegistry} 전용 기능.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-07-09
 */
public interface OIDCAutoTokenChecker {
    /**
     * 토큰 갱신이 필요한지를 결정
     * @param oidcSession OIDC Session 객체
     * @param idpTimeoutSec IDP Timeout 설정 값 (설정에 따라 사용하지 않는 값이 될수 있음)
     * @param skewSec 여유 시간 : 60초로 설정할 경우 만료 시각까지 시간이 60초 이내인 경우 토큰 갱신으로 판정.
     * @return 토큰 갱신이 필요할 경우 True, 아닌 경우 False
     */
    boolean needToRefreshTokens(OIDCSession oidcSession, final int idpTimeoutSec, final int skewSec);
}

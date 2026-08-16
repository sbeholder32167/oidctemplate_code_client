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
package io.github.sbeholder32167.oidctemplate.adapter;

import io.github.sbeholder32167.oidctemplate.client.OIDCTokenTransferObject;
import io.github.sbeholder32167.oidctemplate.client.exception.RBACException;

/**
 * 토큰 세션 변환 어댑터 Interface.<br>
 *
 * <p>주어진 토큰을 이용하여 인증 객체를 만들고 생성하는 Interface<br>
 * 각 Client마다 세션에 포함되는 객체와 정보가 다르기에, 여기서 클라이언트 별로 구현하여 인증 객체를 생성해야 한다.<br><br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-30
 */
public interface ClientAuthConvertAdapter {
    /**
     * 토큰 내용을 이용하여 세션을 구성할 인증 객체를 리턴<br>
     * 인증 객체 내부에 어떤 내용이 포함될지는 각기 Client마다 다르다.<br>
     * Spring Security를 사용하는 경우, Authentication Provider에서 호출되며,<br>
     * Controller 방식을 사용하는 경우, 토큰을 얻은 후 호출된다.<br>
     * 예를들어, DB를 조회하여 인증 객체를 만든다면, 여기가 적합하다.<br>
     * 만약 전자정부프레임워크의 DB 권한 관리 테이블과 매핑이 필요하다면 여기서 DB 조회 후 추가 매핑<br>
     * Spring Security를 사용하는 경우에는 인증 객체인 Authentication을 리턴하도록 구현하고,<br>
     * Spring Security를 사용하지 않는 경우에는 사용중인 Legacy 세션 객체를 리턴하도록 구현한다.<br>
     * @param tto OIDC Token 객체
     * @return Authentication 구현체(Spring Security) 또는 Legacy 세션 객체(Non-Spring Security)
     * @throws RBACException 토큰등이나 각종 정보들이 정상적으로 유입되지 않았을경우 토큰을 만들 수 없다. 그때 던져진다.
     */
    Object buildAuthenticationUsingToken(final OIDCTokenTransferObject tto) throws RBACException;
}

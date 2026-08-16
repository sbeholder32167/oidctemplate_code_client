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
package io.github.sbeholder32167.oidctemplate.egov;

import io.github.sbeholder32167.oidctemplate.client.security.OIDCAuthenticationProvider;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

/**
 * OIDC Provider Injector. (Egov-Security Tag 대응)<br>
 *
 * <p>Egov. Framework에 적용 시 egov-security Tag를 사용하여 Spring Security 설정을 적용하고 있을 경우에 사용됨.<br>
 * Bean들이 모두 생성되었을때 , OIDC Authentication Provider를 적용해준다.<br>
 * OIDC Authentication Provider는 Authentication Manager에 삽입된다.<br>
 * Spring Security의 Authentication Manager Bean 이름은 org.springframework.security.authenticationManager이다.<br>
 * egov-security Tag 이용 환경 전용.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-07-05
 */
//-- XML Bean 등록
public class OIDCProviderInjector implements ApplicationListener<ContextRefreshedEvent> {
    private final OIDCAuthenticationProvider oidcAuthenticationProvider;
    public OIDCProviderInjector(OIDCAuthenticationProvider oidcAuthenticationProvider){
        this.oidcAuthenticationProvider = oidcAuthenticationProvider;
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        if (event.getApplicationContext().getParent() == null) {
            try {
                //-- eGov가 생성한 authenticationManager를 직접 ID나 타입으로 획득
                ProviderManager manager = event.getApplicationContext().getBean("org.springframework.security.authenticationManager", ProviderManager.class);
                List<AuthenticationProvider> providers = new ArrayList<AuthenticationProvider>(manager.getProviders());
                if (!providers.contains(oidcAuthenticationProvider)) {
                    providers.add(0, oidcAuthenticationProvider);

                    //-- Injection using reflection.
                    Field field = ProviderManager.class.getDeclaredField("providers");
                    field.setAccessible(true);
                    field.set(manager, providers);
                    LogUtil.info("OIDC Provider has been injected successfully: Size(" + providers.size() + ")", this);
                }
            } catch (Exception e) {
                LogUtil.error("Failed to inject OIDC Provider:" + e.getLocalizedMessage(), this);
            }
        }
    }
}

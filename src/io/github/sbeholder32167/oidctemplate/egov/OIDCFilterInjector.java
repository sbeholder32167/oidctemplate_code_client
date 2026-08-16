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

import io.github.sbeholder32167.oidctemplate.client.OIDCLogoutFilter;
import io.github.sbeholder32167.oidctemplate.client.security.OIDCLoginFilter;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import java.util.List;
import javax.servlet.Filter;

/**
 * OIDC Filter Injector.(Egov-Security Tag 대응)<br>
 *
 * <p>Egov. Framework에 적용 시 egov-security Tag를 사용하여 Spring Security 설정을 적용하고 있을 경우에 사용됨.<br>
 * 각 Bean이 생성될 때 확인하고, Filter를 적용해준다.<br>
 * Login Filter는 UsernamePasswordAuthenticationFilter 위치에 삽입되고,<br>
 * Logout Filter는 LogoutFilter 위치에 삽입된다.<br>
 * egov-security Tag 이용 환경 전용.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-07-05
 */
//-- XML Bean 등록.
public class OIDCFilterInjector implements BeanPostProcessor {
    private final OIDCLoginFilter oidcLoginFilter;
    private final OIDCLogoutFilter oidcLogoutFilter;
    public OIDCFilterInjector(OIDCLoginFilter oidcLoginFilter, OIDCLogoutFilter oidcLogoutFilter) {
        this.oidcLoginFilter = oidcLoginFilter;
        this.oidcLogoutFilter = oidcLogoutFilter;
    }

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        //-- inject OIDC Filter to filter chain.
        if (/*beanName.equals("org.springframework.security.filterChainProxy") || */
                bean instanceof FilterChainProxy) {
            try {
                FilterChainProxy filterChainProxy = (FilterChainProxy) bean;
                for (SecurityFilterChain chain : filterChainProxy.getFilterChains()) {
                    List<Filter> filters = chain.getFilters();
                    if (!filters.contains(this.oidcLoginFilter)) {
                        for (int i = 0; i < filters.size(); i++) {
                            if (filters.get(i) instanceof UsernamePasswordAuthenticationFilter) {
                                filters.add(i, this.oidcLoginFilter);
                                break;
                            }
                        }
                    }
                }
                for (SecurityFilterChain chain : filterChainProxy.getFilterChains()) {
                    List<Filter> filters = chain.getFilters();
                    if (!filters.contains(this.oidcLogoutFilter)) {
                        for (int i = 0; i < filters.size(); i++) {
                            if (filters.get(i) instanceof LogoutFilter) {
                                filters.add(i, this.oidcLogoutFilter);
                                break;
                            }
                        }
                    }
                }
                LogUtil.info("OIDC Filter has been injected.", this);
            } catch (Exception e) {
                LogUtil.error("Failed to inject OIDC Filter to filter chain.", this);
            }
        }
        return bean;
    }
}

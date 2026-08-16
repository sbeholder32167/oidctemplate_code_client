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
package io.github.sbeholder32167.oidctemplate.client.session;

import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

/**
 * WAS Session의 Event Listener 구현 Class.<br>
 *
 * <p>WAS Session의 Event에 의해 {@link OIDCSessionManager}와 연동하기 위한 Template Class.<br>
 * OIDC Session을 WAS Session에 동기화하기 위한 Class 구현체.<br><br></p>
 *
 * 아래와 같이 web.xml에 설정.<br>
 * <pre>{@code
 * <listener>
 *     <listener-class>
 *         io.github.sbeholder32167.oidctemplate.session.WASSessionEventListener
 *     </listener-class>
 * </listener>}</pre>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-07-10
 */
//-- Deploy to web.xml
public class WASSessionEventListener implements HttpSessionListener {
    private boolean initialized = false;
    private OIDCSessionManager oidcSessionManager;

    private void initialize(HttpSessionEvent se){
        ApplicationContext ctx = WebApplicationContextUtils
                .getRequiredWebApplicationContext(se.getSession().getServletContext());
        this.oidcSessionManager = (OIDCSessionManager)ctx.getBean("OIDCSessionManager");
        this.initialized = true;
    }

    @Override
    public void sessionCreated(HttpSessionEvent se) {
        LogUtil.info("WAS Session created:" + se.getSession().getId(), this);
        if (!this.initialized){
            this.initialize(se);
        }
        LogUtil.info("Session Size:" + this.oidcSessionManager.getSessionCount(), this);
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent se) {
        LogUtil.info("WAS Session Destroyed:" + se.getSession().getId(), this);
        if (!this.initialized){
            this.initialize(se);
        }
        this.oidcSessionManager.expireSessionByEventListener(se.getSession().getId());
        LogUtil.info("Session Size:" + this.oidcSessionManager.getSessionCount(), this);
    }
}

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
package io.github.sbeholder32167.oidctemplate.client.nonsecurity;

import io.github.sbeholder32167.oidctemplate.adapter.ClientLoginAdapter;
import io.github.sbeholder32167.oidctemplate.exception.OIDCException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * OIDC 인증 실패 시 사용되는 Handler Class.<br>
 *
 * <p>Spring Security가 없는 환경에서 사용할 것.<br>
 * Provider / Controller 모두 사용된다.<br>
 * Bean으로 등록되어 사용된다.<br>
 * 필요시 상속 후 재정의하여 사용할 것.</p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-06-29
 */
//-- XML Bean 등록
public class OIDCAuthFailureHandler {
    private final String failureUri;
    public OIDCAuthFailureHandler(final String failureUri){
        this.failureUri = failureUri;
    }

    /**
     * Client Login Adapter 구현체 (Optional)
     */
    private ClientLoginAdapter clientLoginAdapter;
    public void setClientLoginAdapter(final ClientLoginAdapter clientLoginAdapter){
        this.clientLoginAdapter = clientLoginAdapter;
    }

    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, OIDCException exception) throws IOException {
        if (this.clientLoginAdapter != null) {
            this.clientLoginAdapter.doJobFailedLogin(request, response, exception);
        }else{
            response.sendRedirect(request.getContextPath() + this.failureUri);
        }
    }
}

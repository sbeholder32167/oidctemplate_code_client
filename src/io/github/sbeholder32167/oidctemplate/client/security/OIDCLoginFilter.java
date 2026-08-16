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
package io.github.sbeholder32167.oidctemplate.client.security;

import io.github.sbeholder32167.oidctemplate.exception.OIDCException;
import io.github.sbeholder32167.oidctemplate.client.OIDCDataTransferObject;
import io.github.sbeholder32167.oidctemplate.exception.OIDCExceptionHandler;
import io.github.sbeholder32167.oidctemplate.client.provider.OIDCProvider;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import io.github.sbeholder32167.oidctemplate.util.OIDCUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * OIDC Login Filter.<br>
 *
 * <p>Spring Security환경에서 사용되는 OIDC Login Filter 구현체<br>
 * OIDC Authentication Code Flow에 따른 동작을 여기서 진행한다.<br>
 * Authentication Manager의 {@link OIDCAuthenticationProvider}에서 후속 Logic이 진행된다.<br>
 * Bean으로 등록하여 사용<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-07-12
 * @see OIDCAuthenticationProvider
 */
//-- XML Bean 등록
public class OIDCLoginFilter extends AbstractAuthenticationProcessingFilter{
    private final String entryUri;
    private final String redirectUri;
    private final OIDCProvider oidcProvider;

    public OIDCLoginFilter(final String entryEndpoint, final String redirectEndpoint,
                           final OIDCProvider oidcProvider){
        super(new OrRequestMatcher(
            new AntPathRequestMatcher(entryEndpoint),
            new AntPathRequestMatcher(redirectEndpoint)
        ));
        this.entryUri = entryEndpoint;
        this.redirectUri = redirectEndpoint;
        this.oidcProvider = oidcProvider;
    }

    private OIDCExceptionHandler exceptionHandler;
    public void setExceptionHandler(final OIDCExceptionHandler exceptionHandler){
        this.exceptionHandler = exceptionHandler;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        final String requestURI = request.getRequestURI();
        if (requestURI.contains(this.entryUri)) {
            //-- Entry Logic
            try {
                this.oidcProvider.redirectIDPAuthPage(request, response, this.redirectUri);
            }catch(OIDCException oe){
                LogUtil.error(oe.getLocalizedMessage(), this);
                if (this.exceptionHandler != null){
                    this.exceptionHandler.handleException(oe.getStep(), oe, request, response);
                }
            }
            return null;
        }else if (requestURI.contains(this.redirectUri)) {
            //-- Redirect Logic
            OIDCDataTransferObject dto;
            try {
                dto = this.oidcProvider.checkParameters(request);
            }catch(OIDCException oe){
                LogUtil.error(oe.getLocalizedMessage(), this);
                if (this.exceptionHandler != null){
                    this.exceptionHandler.handleException(oe.getStep(), oe, request, response);
                }
                return null;
            }
            //-- Session refresh section.(if required)
            //-- set Servlet request Session ID after refresh.
            String sessionId;
            try {
                sessionId = OIDCUtil.extractSessionId(request);
            } catch (OIDCException e) {
                LogUtil.error(e.getLocalizedMessage(), this);
                return null;
            }
            dto.setSessionId(sessionId);
            //-- go to OIDC Authentication Provider by OIDCAuthentication Object.
            OIDCAuthenticationToken authRequest = new OIDCAuthenticationToken(dto.getCode(), dto);
            return this.getAuthenticationManager().authenticate(authRequest);
        }
        return null;
    }
}
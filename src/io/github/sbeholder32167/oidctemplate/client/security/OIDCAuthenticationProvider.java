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

import io.github.sbeholder32167.oidctemplate.adapter.ClientAuthConvertAdapter;
import io.github.sbeholder32167.oidctemplate.exception.OIDCException;
import io.github.sbeholder32167.oidctemplate.exception.OIDCExceptionEnum;
import io.github.sbeholder32167.oidctemplate.client.OIDCDataTransferObject;
import io.github.sbeholder32167.oidctemplate.client.OIDCTokenTransferObject;
import io.github.sbeholder32167.oidctemplate.client.exception.RBACException;
import io.github.sbeholder32167.oidctemplate.client.provider.OIDCProvider;
import io.github.sbeholder32167.oidctemplate.client.tokens.OIDCTokens;
import io.github.sbeholder32167.oidctemplate.client.tokens.impl.KeycloakTokens;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSessionManager;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;

/**
 * OIDC 인증 Provider.<br>
 *
 * <p>Spring Security의 Authentication Provider를 구현한 Class.<br>
 * {@link OIDCLoginFilter}에서 전달된 파라미터로 토큰을 취득하고 JWKS 검증을 진행한다.<br>
 * 검증이 완료된 후 OIDC 세션을 등록하고 {@link ClientAuthConvertAdapter} 구현체로 전달한다<br>
 * 그 구현체에서 리턴된 Authentication 객체가 Spring Security Session에 반영된다.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-06-28
 * @see ClientAuthConvertAdapter
 */
public class OIDCAuthenticationProvider implements AuthenticationProvider {
    //-- OIDC Provider
    private final OIDCProvider oidcProvider;
    //-- User Customized Token Convert Adapter.
    private final ClientAuthConvertAdapter clientAuthConvertAdapter;
    //-- OIDC Session Manager
    private final OIDCSessionManager oidcSessionManager;

    public OIDCAuthenticationProvider(final OIDCProvider provider, ClientAuthConvertAdapter clientAuthConvertAdapter,
                                      OIDCSessionManager oidcSessionManager){
        this.oidcProvider = provider;
        this.clientAuthConvertAdapter = clientAuthConvertAdapter;
        this.oidcSessionManager = oidcSessionManager;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OIDCAuthenticationToken dummyToken = (OIDCAuthenticationToken)authentication;
        String code = String.valueOf(dummyToken.getPrincipal()==null ? "":dummyToken.getPrincipal());
        OIDCDataTransferObject dto = (OIDCDataTransferObject)dummyToken.getCredentials();
        if (code.isEmpty() || dto == null){
            throw new InsufficientAuthenticationException("Redirect Parameters:Code.");
        }

        OIDCTokenTransferObject tto = null;
        try {
            tto = this.oidcProvider.acquireTokens(dto, null);
        } catch (OIDCException e) {
            if (e.getStep() == OIDCExceptionEnum.NULL_TOKEN_RESPONSE){
                throw new InsufficientAuthenticationException("Null token response.");
            }else if (e.getStep() == OIDCExceptionEnum.INSUFFICIENT_TOKEN){
                throw new InsufficientAuthenticationException("Invalid token response.");
            }
        }
        if (tto == null){
            throw new InsufficientAuthenticationException("Null token response.");
        }

        //-- Token verify process (JWKS, aud)
        try{
            this.oidcProvider.verifyToken(tto.getIdToken(), true);
            this.oidcProvider.verifyToken(tto.getAccessToken(), false);
        } catch (OIDCException e) {
            LogUtil.error("JWKS Error:" + e.getStep().name() + "-" + e.getMessage(), this);
            throw new BadCredentialsException("Token verify failed.");
        }

        //-- OIDC Session Register
        try {
            OIDCTokens oidcTokens = new KeycloakTokens(tto);
            this.oidcSessionManager.registerOIDCSession(oidcTokens.getSid(), dto.getSessionId(), oidcTokens);
        }catch(OIDCException oe){
            //-- Session duplicate.
            LogUtil.error("Session Duplicate:" + oe.getMessage(), this);
            throw new SessionAuthenticationException(oe.getLocalizedMessage());
        }

        //-- Convert(Wrap) to authentication Object from Token Transfer Object.
        try {
            Object resultAuthentication = this.clientAuthConvertAdapter.buildAuthenticationUsingToken(tto);
            if (!(resultAuthentication instanceof Authentication)){
                throw new AuthenticationServiceException("Converter has Not implemented correctly.");
            }
            return (Authentication)resultAuthentication;
        } catch (RBACException e) {
            throw new AuthenticationServiceException(e.getLocalizedMessage());
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(OIDCAuthenticationToken.class);
    }
}
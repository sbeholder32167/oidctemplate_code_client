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
package io.github.sbeholder32167.oidctemplate.client;

import io.github.sbeholder32167.oidctemplate.adapter.ClientLogoutAdapter;
import io.github.sbeholder32167.oidctemplate.exception.OIDCException;
import io.github.sbeholder32167.oidctemplate.exception.OIDCExceptionEnum;
import io.github.sbeholder32167.oidctemplate.exception.OIDCExceptionHandler;
import io.github.sbeholder32167.oidctemplate.client.provider.OIDCProvider;
import io.github.sbeholder32167.oidctemplate.client.session.OIDCSessionManager;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * OIDC Logout 처리 Filter Class.<br>
 *
 * <p>OIDC 로그아웃 동작을 처리하는 Logic이 구현된 Class.<br>
 * IDP에 동시 로그아웃을 요청하는 Logic과, IDP에서의 로그아웃 명령을 수행하는 Logic이 모두 포함됨.<br>
 * Spring Security 존재 여부에 관련없이 동작.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-07-13
 */
//-- XML Bean 등록
public class OIDCLogoutFilter extends OncePerRequestFilter {
    private final OIDCProvider oidcProvider;
    private final OIDCSessionManager oidcSessionManager;
    private final ClientLogoutAdapter clientLogoutAdapter;
    public OIDCLogoutFilter(final OIDCProvider oidcProvider, final OIDCSessionManager oidcSessionManager,
                            ClientLogoutAdapter clientLogoutAdapter){
        this.oidcProvider = oidcProvider;
        this.oidcSessionManager = oidcSessionManager;
        this.clientLogoutAdapter = clientLogoutAdapter;
    }

    /**
     * 사용자 수동 Logout Endpoint URI
     */
    private String manualLogoutUri = "/manual_logout.do";
    public void setManualLogoutUri(final String manualLogoutUri){
        this.manualLogoutUri = manualLogoutUri;
    }

    /**
     * IDP Front / Back Channel Logout Endpoint URI
     */
    private String idpLogoutUri = "/logout.do";
    public void setIdpLogoutUri(final String idpLogoutUri){
        this.idpLogoutUri = idpLogoutUri;
    }

    /**
     * 예외 처리 핸들러
     */
    private OIDCExceptionHandler exceptionHandler;
    public void setExceptionHandler(final OIDCExceptionHandler exceptionHandler){
        this.exceptionHandler = exceptionHandler;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String requestURI = request.getRequestURI();
        if (requestURI.contains(this.manualLogoutUri)) {
            try {
                this.oidcProvider.doOutboundIDPLogout(request, response, this.oidcSessionManager, this.clientLogoutAdapter);
            } catch (OIDCException e) {
                this.handleException(e, request, response);
            }catch (IOException e) {
                LogUtil.error("Exception while OIDC Logout:redirect Exception", this);
                if (this.exceptionHandler != null){
                    this.exceptionHandler.handleException(OIDCExceptionEnum.IDP_LOGOUT_EXCEPTION, e, request, response);
                }else{
                    response.sendRedirect("/");
                }
            }
        } else if (requestURI.contains(this.idpLogoutUri)) {
            try{
                this.oidcProvider.doInboundIDPLogout(request, response, this.oidcSessionManager, this.clientLogoutAdapter);
            }catch (OIDCException e) {
                this.handleException(e, request, response);
            }
        }else{
            filterChain.doFilter(request, response);
        }
    }

    private void handleException(OIDCException oe, HttpServletRequest request, HttpServletResponse response) throws IOException {
        LogUtil.error("Exception while OIDC Logout:" + oe.getMessage(), this);
        if (this.exceptionHandler != null){
            this.exceptionHandler.handleException(oe.getStep(), oe, request, response);
        }else{
            response.sendRedirect("/");
        }
    }
}
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

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OIDC 인증 진행 중 Spring Security Context에 접근하는 메서드 모음<br>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-06-28
 */
public class OIDCContextUtil {
    private OIDCContextUtil(){}
    private static final HttpSessionSecurityContextRepository repository = new HttpSessionSecurityContextRepository();
    /**
     * Spring Security Context Holder에 인증 객체를 수동으로 생성 후 저장<br>Controller 방식 전용.<br>Provider 방식은 Framework에서 해준다
     * @param authentication 인증 객체. 실제 Authentication 객체 구현함
     * @param req HttpServletRequest
     * @param res HttpServletResponse
     */
    public static void generateOIDCSecurityContext(Authentication authentication, HttpServletRequest req, HttpServletResponse res){
        SecurityContextHolder.clearContext();
        SecurityContext sCo = SecurityContextHolder.createEmptyContext();
        sCo.setAuthentication(authentication);
        SecurityContextHolder.setContext(sCo);
        repository.saveContext(sCo, req, res);
    }
    /**
     * Spring Security Context Holder에 인증 객체를 수동으로 갱신<br>Controller 방식 전용.<br>Provider 방식은 Framework에서 해준다
     * @param authentication 인증 객체. 실제 Authentication 객체 구현함
     * @param req HttpServletRequest
     * @param res HttpServletResponse
     */
    public static void refreshOIDCSecurityContext(Authentication authentication, HttpServletRequest req, HttpServletResponse res){
        SecurityContext sCo = SecurityContextHolder.getContext();
        sCo.setAuthentication(authentication);
        SecurityContextHolder.setContext(sCo);
        repository.saveContext(sCo, req, res);
    }
}

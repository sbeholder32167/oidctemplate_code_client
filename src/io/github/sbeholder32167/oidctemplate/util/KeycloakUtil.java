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
package io.github.sbeholder32167.oidctemplate.util;

import com.auth0.jwt.interfaces.Claim;
import io.github.sbeholder32167.oidctemplate.client.OIDCConfig;
import io.github.sbeholder32167.oidctemplate.client.tokens.OIDCTokens;
import io.github.sbeholder32167.oidctemplate.rest.RestfulUtil;
import org.springframework.http.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Keycloak IDP 전용 Utility 메서드 모음.<br>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-30
 */
public class KeycloakUtil {
    private KeycloakUtil(){}
    /**
     * Access Token 또는 다른 토큰을 참조하여 Role 정보를 파싱한다.<br> Client Role만 추출한다<br>
     * Keycloak 전용 Util<br>
     * @param clientId Client Id
     * @param claims AccessToken의 Claim
     * @return Role String List.
     */
    public static List<String> extractClientRolesFromClaims(final String clientId, Map<String, Claim> claims) {
        try {
            Claim resourceAccessClaim = claims.get("resource_access");
            if (resourceAccessClaim == null || resourceAccessClaim.isNull()) {
                return null;
            }

            Map<String, Object> resourceAccessMap = resourceAccessClaim.asMap();
            Object clientData = resourceAccessMap.get(clientId);
            if (!(clientData instanceof Map)) {
                return null;
            }

            Map<?, ?> clientRoleMap = (Map<?, ?>) clientData;
            Object rolesData = clientRoleMap.get("roles");
            if (!(rolesData instanceof List)) {
                return null;
            }

            List<?> rawList = (List<?>) rolesData;
            //return rawList.stream().filter(String.class::isInstance)
            //        .map(String.class::cast).collect(Collectors.toList());
            //-- Under JDK 1.8
            return (List<String>)rolesData;
        }catch (Exception je){
            LogUtil.error("JWT Decode Exception:" + je.getLocalizedMessage(), KeycloakUtil.class.getName());
            return null;
        }
    }
    /**
     * Access Token 또는 다른 토큰을 참조하여 Role 정보를 파싱한다.<br> Realm Role만 추출한다<br>
     * Keycloak 전용 Util<br>
     * @param claims AccessToken의 Claim
     * @return Role String List.
     */
    public static List<String> extractRealmRolesFromClaims(Map<String, Claim> claims) {
        try {
            Claim realmAccessClaim = claims.get("realm_access");
            if (realmAccessClaim == null || realmAccessClaim.isNull()) {
                return null;
            }

            Map<String, Object> realmAccessMap = realmAccessClaim.asMap();
            Object rolesData = realmAccessMap.get("roles");
            if (!(rolesData instanceof List)) {
                return null;
            }

            List<?> rawList = (List<?>) rolesData;
            //return rawList.stream().filter(String.class::isInstance)
            //        .map(String.class::cast).collect(Collectors.toList());
            //-- Under JDK 1.8
            return (List<String>)rolesData;
        } catch (Exception e) {
            LogUtil.error("Keycloak Realm Role Extraction Exception: " + e.getLocalizedMessage(), KeycloakUtil.class.getName());
            return null;
        }
    }

    /**
     * Logout Token으로부터 SID를 추출한다.<br>
     * JWKS 검증을 같이 진행한다<br>
     * Keycloak 전용 Util<br>
     * @param logoutToken IDP로부터 전송된 logout Token
     * @return 추출한 SID를 리턴한다. SID가 없거나 JWKS 검증이 실패할 경우 null.
     */
    public static String extractSidFromLogoutToken(final String logoutToken){
        Map<String, Claim> logoutClaimMap = OIDCUtil.parseJwtPayload(logoutToken);
        if(logoutClaimMap == null){
            LogUtil.error("logout token parse failed.", KeycloakUtil.class.getName());
            return null;
        }
        Claim sidClaim = logoutClaimMap.get("sid");
        if (sidClaim == null){
            LogUtil.error("extracting sid has failed.", KeycloakUtil.class.getName());
            return null;
        }
        return sidClaim.asString();
    }

    /**
     * Back Channel Post IDP Logout
     * @param restfulUtil Restful 객체.
     * @param config OIDC Config bean 객체.
     * @param oidcTokens 세션 내 인증 객체.
     */
    public static void logoutIDP(RestfulUtil restfulUtil, OIDCConfig config, OIDCTokens oidcTokens){
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        Map<String, String> bodyParam = new HashMap<String, String>();
        bodyParam.put("client_id", config.getClientId());
        bodyParam.put("client_secret", config.getClientSecret());
        bodyParam.put("refresh_token", oidcTokens.getRefreshToken());
        ResponseEntity<String> response = restfulUtil.doRestful(config.getLogoutUri(), HttpMethod.POST, headers, bodyParam, String.class);
        if (response.getStatusCode() == HttpStatus.OK || response.getStatusCode() == HttpStatus.NO_CONTENT){
            LogUtil.info("IDP Logout successfully.", KeycloakUtil.class.getName());
        }else{
            //LogUtil.info("IDP Logout:" + response.getStatusCodeValue(), KeycloakUtil.class.getName());
            //-- Under JDK 1.8
            LogUtil.info("IDP Logout:" + response.getStatusCode().value(), KeycloakUtil.class.getName());
        }
    }
}
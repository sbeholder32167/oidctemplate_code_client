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
package io.github.sbeholder32167.oidctemplate.jwks;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.github.sbeholder32167.oidctemplate.jwks.exception.JWKSException;
import io.github.sbeholder32167.oidctemplate.rest.RestfulUtil;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * JWKS 검증 Class.<br>
 *
 * <p>RSA 알고리즘으로 JWKS 검증하는 로직이 구현된 Class.</p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-26
 */
public class RSAJWKSVerifier {
    private RSAJWKSVerifier(){}
    /**
     * 토큰을 검증한다.<br>
     * HS512 알고리즘의 Refresh Token은 검증 대상이 아님.<br>
     * 오로지 RSA 만 검증할수 있으므로 참고.<br>
     * 주의 : Keycloak IDP에서만 테스트됨.<br>
     * @since 2025-11-02<br>
     * @param restUtil RestFulUtil 객체.
     * @param jwksEndpoint Keycloak Certification의 URL String.
     * @param token AccessToken을 의미. IDToken의 유효성도 검증할수는 있긴 하다.
     * @param clientId Audience값과 비교하고 싶다면 clientId를 넣을것. 비교하기 싫다면 null을 넣으면 된다.
     * @exception JWKSException JWKS 단계의 모든 부분에서 예외를 이 방식으로 던진다.
     */
    public static void verifyToken(final RestfulUtil restUtil, final String jwksEndpoint,
                                      final String token, final String clientId) throws JWKSException {
        //-- check Signature Algorithm..
        DecodedJWT decodedTkn;
        try{
            decodedTkn = JWT.decode(token);
        }catch(com.auth0.jwt.exceptions.JWTDecodeException jwtDecodeException){
            throw new JWKSException(JWKSErrorEnum.DECODE_JWT, jwtDecodeException.getLocalizedMessage());
        }
        String algStr = decodedTkn.getAlgorithm();
        if (algStr == null ){
            throw new JWKSException(JWKSErrorEnum.NULL_ALG, "Not found algorithm");
        }else if (algStr.isEmpty() || algStr.trim().isEmpty()){
            throw new JWKSException(JWKSErrorEnum.NO_ALG, "Empty algorithm");
        }
        LogUtil.info("Token Signature Algorithm:" + algStr, RSAJWKSVerifier.class.getName());

        //-- check audience
        if (clientId != null && !clientId.trim().isEmpty()){
            //-- 체크하라고 Client ID를 넣어줘야 동작하게 했다. null일 경우엔 검사하지 않고 Skip한다.
            boolean isInAudience = false;
            List<String> audLst = decodedTkn.getAudience();
            if (audLst == null){
                throw new JWKSException(JWKSErrorEnum.NULL_AUDIENCE, "Null Audience List.");
            }else {
                for (String aud : audLst){
                    if (aud.trim().equals(clientId.trim())){
                        isInAudience = true;
                        break;
                    }
                }
            }
            if (!isInAudience){
                throw new JWKSException(JWKSErrorEnum.INVALID_AUDIENCE, "Client ID is not in Audience List.");
            }
            LogUtil.info("Client ID is exist in Audience List.", RSAJWKSVerifier.class.getName());
        }
        //-- prepare to fetch JSON Web Key set.
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        ResponseEntity<Map> response = restUtil.doRestful(jwksEndpoint, HttpMethod.GET, headers, null, Map.class);
        if (response == null){
            throw new JWKSException(JWKSErrorEnum.NULL_JWKS_RESPONSE, "Null JWKS response");
        }
        LogUtil.info("JWKS access Status : " + response.getStatusCode().value(), RSAJWKSVerifier.class.getName());
        Map<?,?> data = response.getBody();
        if (response.getStatusCode().value() != 200 || data == null){
            throw new JWKSException(JWKSErrorEnum.FAILED_JWKS_RESPONSE, "JWKS Endpoint process has failed.");
        }

        boolean foundCerts = false;
        String certStr = null;
        @SuppressWarnings("unchecked")
        List<Object> rootLst = (List<Object>)data.get("keys");
        if (rootLst == null){
            throw new JWKSException(JWKSErrorEnum.NO_KEYS, "Null JWKS Keys.");
        }
        for (Object o : rootLst){
            @SuppressWarnings("unchecked")
            Map<String, Object> el = (Map<String, Object>)o;
            if (el != null && el.get("alg") != null && String.valueOf(el.get("alg")).equals(algStr)){
                @SuppressWarnings("unchecked")
                List<String> certCoverLst = (List<String>) el.get("x5c");
                certStr = certCoverLst.get(0);
                // NOSONAR System.out.println("JWKS Cert Str : " + certStr);
                foundCerts = true;
                break;
            }
        }
        PublicKey pk;
        if (!foundCerts){
            throw new JWKSException(JWKSErrorEnum.NO_CERTS, "Not found certification.");
        }
        CertificateFactory certFactory;
        try {
            certFactory = CertificateFactory.getInstance("X.509");
            byte[] decodedCerts = Base64.getDecoder().decode(certStr);
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(decodedCerts));
            pk = certificate.getPublicKey();
        } catch (CertificateException e) {
            throw new JWKSException(JWKSErrorEnum.GEN_CERTS_ERR, "Certificate Exception" + e.getLocalizedMessage());
        }
        if (pk == null){
            throw new JWKSException(JWKSErrorEnum.EXT_CERTS_ERR, "Can`t extract Public key from certificate.");
        }
        try {
            Algorithm algObj;
            switch (algStr) {
                case "RS256":
                    algObj = Algorithm.RSA256((RSAPublicKey) pk, null);
                    algObj.verify(decodedTkn);
                    break;
                case "RS384":
                    algObj = Algorithm.RSA384((RSAPublicKey) pk, null);
                    algObj.verify(decodedTkn);
                    break;
                case "RS512":
                    algObj = Algorithm.RSA512((RSAPublicKey) pk, null);
                    algObj.verify(decodedTkn);
                    break;
                default:
                    throw new JWKSException(JWKSErrorEnum.NOT_SUPPORTED_ALG, "Unknown Encrypt Algorithm : " + algStr);
            }
        }catch (SignatureVerificationException e){
            throw new JWKSException(JWKSErrorEnum.INVALID_SIG, "Signature Verification ERROR:" + e.getLocalizedMessage());
        }
    }
}

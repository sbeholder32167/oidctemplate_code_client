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
import org.springframework.util.Base64Utils;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * JWKS 검증 Class.<br>
 *
 * <p>RSA 알고리즘으로 JWKS 검증하는 로직이 구현된 Class.</p>
 *
 * @author sbeholder6684
 * @version 1.0.2
 * @since 2026-05-26
 */
public class RSAJWKSVerifier {
    private RSAJWKSVerifier(){}

    /**
     * 토큰을 검증한다.<br>
     * HS512 알고리즘의 Refresh Token은 검증 대상이 아님.<br>
     * 오로지 RSA 만 검증할수 있으므로 참고.<br>
     * Public Key 생성 시 Key Algorithm을 Keyset과 비교한다.<br><br>
     * Keycloak Test 2025-11-02.<br>
     * Google Test 2026-08-20.<br>
     * Naver Test 2026-09-05.<br>
     *
     * @since 2025-11-02<br>
     * @param restUtil RestFulUtil 객체.
     * @param jwksEndpoint Keycloak Certification의 URL String.
     * @param token AccessToken을 의미. IDToken의 유효성도 검증할수는 있긴 하다.
     * @param clientId Audience값과 비교하고 싶다면 clientId를 넣을것. 비교하기 싫다면 null을 넣으면 된다.
     * @exception JWKSException JWKS 단계의 모든 부분에서 예외를 이 방식으로 던진다.
     */
    public static void verifyToken(final RestfulUtil restUtil, final String jwksEndpoint,
                                   final String token, final String clientId) throws JWKSException{
        verifyToken(restUtil, jwksEndpoint, token, clientId, false);
    }
    /**
     * 토큰을 검증한다.<br>
     * HS512 알고리즘의 Refresh Token은 검증 대상이 아님.<br>
     * 오로지 RSA 만 검증할수 있으므로 참고.<br>
     * <br><br>
     * Keycloak Test 2025-11-02.<br>
     * Google Test 2026-08-20.<br>
     * Naver Test 2026-09-05.<br>
     *
     * @since 2025-11-02<br>
     * @param restUtil RestFulUtil 객체.
     * @param jwksEndpoint Keycloak Certification의 URL String.
     * @param token AccessToken을 의미. IDToken의 유효성도 검증할수는 있긴 하다.
     * @param clientId Audience값과 비교하고 싶다면 clientId를 넣을것. 비교하기 싫다면 null을 넣으면 된다.
     * @param skipCheckAlg Header의 Algorithm과 Key Set의 Algorithm 비교 로직을 건너뛴다.
     * @exception JWKSException JWKS 단계의 모든 부분에서 예외를 이 방식으로 던진다.
     */
    public static void verifyToken(final RestfulUtil restUtil, final String jwksEndpoint,
                                   final String token, final String clientId, boolean skipCheckAlg) throws JWKSException {
        //-- check Signature Algorithm..
        DecodedJWT decodedTkn;
        try{
            decodedTkn = JWT.decode(token);
        }catch(com.auth0.jwt.exceptions.JWTDecodeException jwtDecodeException){
            throw new JWKSException(JWKSErrorEnum.DECODE_JWT, jwtDecodeException.getLocalizedMessage());
        }
        String algStr = decodedTkn.getAlgorithm();
        if (algStr == null){
            throw new JWKSException(JWKSErrorEnum.NULL_ALG, "Not found algorithm");
        }else if (algStr.isEmpty() || algStr.trim().isEmpty()){
            throw new JWKSException(JWKSErrorEnum.NO_ALG, "Empty algorithm");
        }
        LogUtil.info("Token Signature Algorithm:" + algStr, RSAJWKSVerifier.class.getName());
        String keyId = decodedTkn.getHeaderClaim("kid").asString();

        //-- check audience
        if (clientId != null && !clientId.trim().isEmpty()){
            //-- Client ID가 지정되었을 때만 동작. null일 경우엔 검사하지 않고 Skip한다.
            checkAudience(decodedTkn, clientId);
        }
        //-- query JSON Web Key set.
        List<Object> rootLst = queryJWKS(restUtil, jwksEndpoint);
        if (rootLst == null){
            throw new JWKSException(JWKSErrorEnum.NO_KEYS, "Null JWKS Keys.");
        }
        if (skipCheckAlg) {
            //-- to parse Naver JWKS as omitted alg claim.
            checkKeysList(rootLst, algStr);
        }
        PublicKey pk = findCertsInKeyList(rootLst, algStr, keyId);
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

    /**
     * Audience Claim이 주어진 Client ID와 일치하는지 검증
     * @param decodedToken Decoded Token
     * @param clientId Client ID
     * @throws JWKSException Audience 리스트가 없거나, Audience가 일치하지 않을 경우 발생.
     */
    private static void checkAudience(DecodedJWT decodedToken, final String clientId) throws JWKSException {
        //-- Client ID가 지정되었을 때만 동작. null일 경우엔 검사하지 않고 Skip한다.
        boolean isInAudience = false;
        List<String> audLst = decodedToken.getAudience();
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

    /**
     * JSON Web Key set을 받아온다
     * @param restfulUtil Restful 객체.
     * @param jwksUri JWKS Endpoint URI
     * @return JSON Web key Set List
     * @throws JWKSException Null respoinse 또는 query가 실패했을 경우 발생.
     */
    private static List<Object> queryJWKS(final RestfulUtil restfulUtil, final String jwksUri) throws JWKSException {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        ResponseEntity<Map> response = restfulUtil.doRestful(jwksUri, HttpMethod.GET, headers, null, Map.class);
        if (response == null){
            throw new JWKSException(JWKSErrorEnum.NULL_JWKS_RESPONSE, "Null JWKS response");
        }
        LogUtil.info("JWKS access Status : " + response.getStatusCode().value(), RSAJWKSVerifier.class.getName());
        Map<?,?> data = response.getBody();
        if (response.getStatusCode().value() != 200 || data == null){
            throw new JWKSException(JWKSErrorEnum.FAILED_JWKS_RESPONSE, "JWKS Endpoint process has failed.");
        }
        @SuppressWarnings("unchecked")
        List<Object> result = (List<Object>)data.get("keys");
        return result;
    }

    /**
     * Key List 에서 인증서를 찾는다.<br>
     * @param keyList Key List
     * @param algorithm 알고리즘
     * @param keyId Key ID. Header에서 추출.
     * @return 인증서를 리턴.
     * @throws JWKSException 인증서가 제대로 생성되지 않았거나 인증서 문자열이 없을 경우.
     */
    private static PublicKey findCertsInKeyList(List<Object> keyList, final String algorithm, final String keyId) throws JWKSException{
        for (Object o : keyList){
            @SuppressWarnings("unchecked")
            Map<String, Object> el = (Map<String, Object>)o;
            if (el != null && el.containsKey("alg") && String.valueOf(el.get("alg")).equals(algorithm)){
                if (el.get("x5c") != null){
                    @SuppressWarnings("unchecked")
                    List<String> certCoverLst = (List<String>) el.get("x5c");
                    if (keyId != null){
                        if (keyId.equals(el.get("kid"))){
                            return getPublicKeyFromX5c(certCoverLst.get(0));
                        }
                    }else{
                        //-- Default if no Key id : first element.
                        return getPublicKeyFromX5c(certCoverLst.get(0));
                    }
                }else if (el.get("n") != null && el.get("e") != null){
                    if (keyId != null){
                        if (keyId.equals(el.get("kid"))){
                            return getPublicKeyFromJwk(String.valueOf(el.get("n")), String.valueOf(el.get("e")));
                        }
                    }else{
                        //-- Default if no Key id : first element.
                        return getPublicKeyFromJwk(String.valueOf(el.get("n")), String.valueOf(el.get("e")));
                    }
                }
            }
        }
        throw new JWKSException(JWKSErrorEnum.GEN_CERTS_ERR, "no string to extract certs.");
    }

    private static PublicKey getPublicKeyFromX5c(final String x5cStr) throws JWKSException{
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            //byte[] decodedCerts = Base64.getDecoder().decode(x5cStr);
            //-- Under JDK 1.8
            byte[] decodedCerts = Base64Utils.decodeFromString(x5cStr);
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(decodedCerts));
            return certificate.getPublicKey();
        }catch(CertificateException ce){
            throw new JWKSException(JWKSErrorEnum.GEN_CERTS_ERR, ce.getLocalizedMessage());
        }
    }
    private static PublicKey getPublicKeyFromJwk(final String nStr, final String eStr) throws JWKSException{
        //-- decode Base64URL.
        //byte[] nBytes = Base64.getUrlDecoder().decode(nStr);
        //byte[] eBytes = Base64.getUrlDecoder().decode(eStr);
        //-- Under JDK 1.8
        byte[] nBytes = Base64Utils.decodeFromString(nStr);
        byte[] eBytes = Base64Utils.decodeFromString(eStr);

        //-- convert to BigInteger.
        BigInteger modulus = new BigInteger(1, nBytes);
        BigInteger publicExponent = new BigInteger(1, eBytes);

        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, publicExponent);
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new JWKSException(JWKSErrorEnum.GEN_CERTS_ERR, e.getLocalizedMessage());
        }
    }

    /**
     * Naver의 JWKS Claim 차이로 인해 추가한 메서드<br>
     * 사용을 권장하지는 않지만, Naver Provider에 한하여 적용.<br>
     * @param keyList JWKS Key Set.
     * @param algorithm Algorithm
     */
    private static void checkKeysList(List<Object> keyList, final String algorithm){
        for (Object o : keyList) {
            @SuppressWarnings("unchecked")
            Map<String, Object> el = (Map<String, Object>) o;
            if (!el.containsKey("alg")){
                el.put("alg", algorithm);
            }
        }
    }
}

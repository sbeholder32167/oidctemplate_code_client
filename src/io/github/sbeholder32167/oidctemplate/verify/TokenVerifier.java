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
package io.github.sbeholder32167.oidctemplate.verify;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.github.sbeholder32167.oidctemplate.client.config.OIDCConfig;
import io.github.sbeholder32167.oidctemplate.client.exception.TokenVerifyException;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;

import java.util.List;

/**
 * ID Token 검증 Class.<br>
 *
 * <p>ID Token을 검증하는 로직이 구현된 Class.</p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-10-07
 */
public class TokenVerifier {
    private TokenVerifier(){}

    /**
     * ID Token을 검증한다<br/>
     * 검증 항목은 iss, exp, iat, nbf, aud, azp, nonce이다.
     * @param idToken ID Token
     * @param oidcConfig OIDC Config Bean.
     * @param nonce 인증 Flow 시작 시 서버로 보낸 임의의 값. 없을 경우 비교하지 않는다. 빈칸 또는 null일 수도 있다.
     * @throws TokenVerifyException 검증 실패 시 발생.
     */
    public static void verifyIDToken(final String idToken, final OIDCConfig oidcConfig, final String nonce) throws TokenVerifyException {
        DecodedJWT decodedTkn;
        try{
            decodedTkn = JWT.decode(idToken);
        }catch(com.auth0.jwt.exceptions.JWTDecodeException jwtDecodeException){
            throw new TokenVerifyException(TokenVerifyException.Cause.DECODE_JWT, jwtDecodeException.getLocalizedMessage());
        }
        //-- check issuedAt, expiration time, Not Before time.
        checkIssuedExpirationTime(decodedTkn, oidcConfig.getIatSkewSec());
        //-- check issuer.
        String target = oidcConfig.getIssuer();
        if (target == null || target.isEmpty()){
            throw new TokenVerifyException(TokenVerifyException.Cause.NO_CLAIM, "Issuer not in config.");
        }
        checkIssuer(decodedTkn, target);
        //-- check audience.
        target = oidcConfig.getClientId();
        if (target == null || target.isEmpty()){
            throw new TokenVerifyException(TokenVerifyException.Cause.NO_CLAIM, "Client ID not in config.");
        }
        checkAudience(decodedTkn, target);
        checkAuthorizedParty(decodedTkn, target);
        //-- check Nonce.
        if (nonce != null && !nonce.trim().isEmpty()){
            //-- Nonce가 유입되었을 때만 동작. 없다면 Skip.
            checkNonce(decodedTkn, nonce);
        }
        LogUtil.info("Valid ID Token.(Verified)", TokenVerifier.class.getName());
    }
    /**
     * Access Token을 검증한다<br/>
     * 검증 항목은 iss, exp, iat, nbf, aud, azp이다.
     *
     * @param accessToken Access Token
     * @param oidcConfig OIDC Config Bean.
     * @throws TokenVerifyException 검증 실패 시 발생.
     */
    public static void verifyAccessToken(final String accessToken, final OIDCConfig oidcConfig) throws TokenVerifyException {
        DecodedJWT decodedTkn;
        try {
            decodedTkn = JWT.decode(accessToken);
        } catch (com.auth0.jwt.exceptions.JWTDecodeException jwtDecodeException) {
            throw new TokenVerifyException(TokenVerifyException.Cause.DECODE_JWT, jwtDecodeException.getLocalizedMessage());
        }
        //-- check issuedAt, expiration time, Not Before time.
        checkIssuedExpirationTime(decodedTkn, oidcConfig.getIatSkewSec());
        //-- check Issuer
        String target = oidcConfig.getIssuer();
        if (target == null || target.isEmpty()) {
            throw new TokenVerifyException(TokenVerifyException.Cause.NO_CLAIM, "Issuer not in config.");
        }
        checkIssuer(decodedTkn, target);
        //-- check audience.
        target = oidcConfig.getClientId();
        if (target == null || target.isEmpty()){
            throw new TokenVerifyException(TokenVerifyException.Cause.NO_CLAIM, "Client ID not in config.");
        }
        checkAudience(decodedTkn, target);
        //-- check Authorized Party.
        checkAuthorizedParty(decodedTkn, target);
        LogUtil.info("Valid Access Token.(Verified)", TokenVerifier.class.getName());
    }

    /**
     * Issuer Claim이 주어진 Issuer 값과 일치하는지 검증
     * @param decodedToken Decoded Token
     * @param issuer OIDC Config Issuer. (Discovery에서 찾아옴)
     * @throws TokenVerifyException 발급자(Issuer) Claim이 Config의 Issuer값과 일치하지 않을 경우 발생.
     */
    private static void checkIssuer(DecodedJWT decodedToken, final String issuer) throws TokenVerifyException{
        if (!decodedToken.getIssuer().equals(issuer)){
            throw new TokenVerifyException(TokenVerifyException.Cause.INVALID_ISSUER, "Invalid Issuer.");
        }
        LogUtil.info("Issuer has been checked.(Equal)", TokenVerifier.class.getName());
    }
    /**
     * Audience Claim이 주어진 Client ID와 일치하는지 검증
     * @param decodedToken Decoded Token
     * @param clientId Client ID
     * @throws TokenVerifyException Audience 리스트가 없거나, Audience가 일치하지 않을 경우 발생.
     */
    private static void checkAudience(DecodedJWT decodedToken, final String clientId) throws TokenVerifyException {
        //-- Client ID가 지정되었을 때만 동작. null일 경우엔 검사하지 않고 Skip한다.
        if (clientId == null || clientId.trim().isEmpty()){
            LogUtil.info("Client Id for comparing with Audience is not presented.(Ignored)", TokenVerifier.class.getName());
            return;
        }
        if (decodedToken.getClaim("aud").isNull()){
            LogUtil.info("Audience is not exist in the token.(Ignored)", TokenVerifier.class.getName());
            return;
        }
        boolean isInAudience = false;
        List<String> audLst = decodedToken.getAudience();
        if (audLst == null){
            throw new TokenVerifyException(TokenVerifyException.Cause.NULL_AUDIENCE, "Null Audience List.");
        }else {
            for (String aud : audLst){
                if (aud.trim().equals(clientId.trim())){
                    isInAudience = true;
                    break;
                }
            }
        }
        if (!isInAudience){
            throw new TokenVerifyException(TokenVerifyException.Cause.INVALID_AUDIENCE, "Client ID is not in Audience List.");
        }
        LogUtil.info("Client ID is exist in Audience List.(Valid)", TokenVerifier.class.getName());
    }
    /**
     * Nonce Claim이 주어진 Nonce 값과 일치하는지 검증<br/>
     * Nonce가 있을 때만 동작. null일 경우엔 검사하지 않고 Skip한다.<br/>
     * @param decodedToken Decoded Token
     * @param nonce 인증 Flow 시작 시 서버로 보낸 임의의 값. 없을 경우 비교하지 않는다.
     * @throws TokenVerifyException Nonce가 일치하지 않을 경우 발생.
     */
    private static void checkNonce(DecodedJWT decodedToken, final String nonce) throws TokenVerifyException {
        if (nonce == null || nonce.trim().isEmpty()) return;
        Claim nonceClaim = decodedToken.getClaim("nonce");
        if (nonceClaim.isNull()){
            throw new TokenVerifyException(TokenVerifyException.Cause.NULL_NONCE, "Nonce claim not found in the token.");
        }
        if (!nonceClaim.asString().trim().equals(nonce.trim())){
            throw new TokenVerifyException(TokenVerifyException.Cause.INVALID_NONCE, "Invalid Nonce value.");
        }
        LogUtil.info("Nonce has been checked.(Equal)", TokenVerifier.class.getName());
    }
    /**
     * 발급 / 만료 시각 확인
     * @param decodedToken Decoded Token
     * @throws TokenVerifyException 만료시각이 현재 시각보다 이전이라면 발생.
     */
    private static void checkIssuedExpirationTime(DecodedJWT decodedToken, int skewSec) throws TokenVerifyException {
        long currentTime = System.currentTimeMillis();
        long skewSecMills = skewSec * 1000L;
        if (decodedToken.getExpiresAt().getTime() < currentTime + skewSecMills){
            throw new TokenVerifyException(TokenVerifyException.Cause.ALREADY_EXPIRED, "Token has already expired.");
        }
        if (decodedToken.getIssuedAt().getTime() > currentTime + skewSecMills){
            throw new TokenVerifyException(TokenVerifyException.Cause.INVALID_ISSUED, "Token has issued in future.Invalid token.");
        }
        if (!decodedToken.getClaim("nbf").isNull()){
            if (decodedToken.getNotBefore().getTime() > currentTime + skewSecMills){
                throw new TokenVerifyException(TokenVerifyException.Cause.INVALID_NOT_BEFORE, "Token has issued in future.Invalid token.");
            }
        }
        LogUtil.info("The expiration/issued time of token has been checked.(Valid)", TokenVerifier.class.getName());
    }
    /**
     * 인가 Party (azp)를 검증.
     * @param decodedToken Decoded Token
     * @param clientId Client ID
     * @throws TokenVerifyException 일치하지 않는 경우 발생
     */
    private static void checkAuthorizedParty(DecodedJWT decodedToken, final String clientId) throws TokenVerifyException {
        Claim azpClaim = decodedToken.getClaim("azp");
        if (azpClaim.isNull()){
            LogUtil.info("Authorized Party has been not checked.(Ignored)", TokenVerifier.class.getName());
            return;
        }else{
            if (azpClaim.asString() != null && !(azpClaim.asString().trim().equals(clientId.trim()))){
                throw new TokenVerifyException(TokenVerifyException.Cause.INVALID_AUTHORIZED_PARTY, "Client ID is not equal Authorized Party.");
            }
        }
        LogUtil.info("Authorized Party has been checked.(Equal)", TokenVerifier.class.getName());
    }
}

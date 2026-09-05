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
package io.github.sbeholder32167.oidctemplate.client.provider;

import io.github.sbeholder32167.oidctemplate.client.config.OIDCConfig;
import io.github.sbeholder32167.oidctemplate.client.exception.RBACException;
import io.github.sbeholder32167.oidctemplate.client.tokens.OIDCTokens;
import io.github.sbeholder32167.oidctemplate.rest.RestfulUtil;
import io.github.sbeholder32167.oidctemplate.client.session.storage.OIDCAuthParameterStorage;

/**
 * OIDC 인증 제공자 추상 Class.<br>
 *
 * <p>OIDC 인증에 필요한 동작 및 각종 Parameter와 Logic이 정의된 Class.<br>
 * OIDC Config와 Restful Util Bean을 주입받는다.<br>
 * IDP에 따라 따로 구현되어야 한다.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-07-09
 * @see io.github.sbeholder32167.oidctemplate.client.provider.impl.KeycloakProvider
 */
public abstract class AbstractOIDCProvider implements OIDCProvider{
    protected static final String STATE_ATTR = "OIDC_STATE";
    protected static final String PKCE_ATTR = "PKCE_VERIFIER";
    protected static final String NONCE_ATTR = "NONCE";
    protected static final String ID_TOKEN = "id_token";
    protected static final String EXPIRES_IN = "expires_in";
    protected static final String ACCESS_TOKEN = "access_token";
    protected static final String REFRESH_EXPIRES_IN = "refresh_expires_in";
    protected static final String REFRESH_TOKEN = "refresh_token";

    protected final OIDCConfig oidcConfig;
    protected final RestfulUtil restfulUtil;
    protected final OIDCAuthParameterStorage oidcAuthParameterStorage;
    protected AbstractOIDCProvider(OIDCConfig config, RestfulUtil restfulUtil,
                                   OIDCAuthParameterStorage oidcAuthParameterStorage){
        this.oidcConfig = config;
        this.restfulUtil = restfulUtil;
        this.oidcAuthParameterStorage = oidcAuthParameterStorage;
    }
    /**
     * IDP Claim이 없을 때 Default로 설정할 Access Token 유효시간
     */
    protected int defaultAccessTokenDurationSec = 300;
    public void setDefaultAccessTokenDurationSec(final int defaultAccessTokenDurationSec){
        this.defaultAccessTokenDurationSec = defaultAccessTokenDurationSec;
    }
    /**
     * IDP Claim이 없을 때 Default로 설정할 Refresh Token 유효시간
     */
    protected int defaultRefreshTokenDurationSec = 1800;
    public void setDefaultRefreshTokenDurationSec(final int defaultRefreshTokenDurationSec){
        this.defaultRefreshTokenDurationSec = defaultRefreshTokenDurationSec;
    }

    @Override
    public long extractAccessTokenExpirationTime(final OIDCTokens tokens) throws RBACException {
        long currentTimeSec = System.currentTimeMillis() / 1000;
        return currentTimeSec + tokens.getTokenTransferObj().getExpiresIn();
    }

    @Override
    public long extractRefreshTokenExpirationTime(final OIDCTokens tokens) throws RBACException {
        //-- Extract expiration time for refresh token.
        if (tokens.getRefreshToken() == null || tokens.getRefreshToken().isEmpty()){
            return -1;
        }
        long currentTimeSec = System.currentTimeMillis() / 1000;
        return currentTimeSec + tokens.getTokenTransferObj().getRefreshExpiresIn();
    }
}

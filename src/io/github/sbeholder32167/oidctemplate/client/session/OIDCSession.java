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
package io.github.sbeholder32167.oidctemplate.client.session;

import io.github.sbeholder32167.oidctemplate.client.tokens.OIDCTokens;

/**
 * OIDC Session Object.<br>
 *
 * <p>OIDC Session Storage Session Object.<br>
 * SID, Session ID, 인증 객체들의 구조체.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-06-21
 */
public class OIDCSession {
    private final String sid;
    private final String sessionId;
    private final OIDCTokens tokens;
    private boolean isExpired = false;
    private long lastAccessedTime;
    //-- Time Cache
    private long latestIdptouchTimeSec;
    private long accessTokenExpirationTimeSec;
    private long refreshTokenExpirationTimeSec;

    public OIDCSession(String sid, String sessionId, OIDCTokens tokens,
                       long accessTokenExpirationTimeSec,
                       long refreshTokenExpirationTimeSec){
        this.sid = sid;
        this.sessionId = sessionId;
        this.tokens = tokens;
        this.latestIdptouchTimeSec = System.currentTimeMillis() / 1000;
        this.lastAccessedTime = this.latestIdptouchTimeSec;
        this.accessTokenExpirationTimeSec = accessTokenExpirationTimeSec;
        this.refreshTokenExpirationTimeSec = refreshTokenExpirationTimeSec;
    }
    public String getSid(){return this.sid;}
    public String getSessionId() {return this.sessionId; }
    public boolean isExpired(){return this.isExpired;}
    public void setExpired(boolean expire) {this.isExpired = expire;}
    public OIDCTokens getTokens(){return this.tokens;}
    public long getAccessTokenExpirationTimeSec(){return this.accessTokenExpirationTimeSec;}
    public void setAccessTokenExpirationTimeSec(final long accessTokenExpirationTimeSec){
        this.accessTokenExpirationTimeSec = accessTokenExpirationTimeSec;
    }
    public long getRefreshTokenExpirationTimeSec(){return this.refreshTokenExpirationTimeSec;}
    public void setRefreshTokenExpirationTimeSec(final long refreshTokenExpirationTimeSec){
        this.refreshTokenExpirationTimeSec = refreshTokenExpirationTimeSec;
    }
    public long getLatestIdptouchTimeSec() {
        return latestIdptouchTimeSec;
    }
    public void setLatestIdptouchTimeSec(long latestIdptouchTimeSec) {
        this.latestIdptouchTimeSec = latestIdptouchTimeSec;
    }
    public long getLastAccessedTime(){
        return this.lastAccessedTime;
    }
    public void setLastAccessedTime(long lastAccessedTime){
        this.lastAccessedTime = lastAccessedTime;
    }
}
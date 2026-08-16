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
package io.github.sbeholder32167.oidctemplate.rest.strategy;

import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

/**
 * 인증서 검증 제외 Restful Strategy 구현체 Class.<br>
 *
 * <p>의도적으로 인증서 검증을 하지 않도록 작성<br>
 * 개발 / 테스트시에만 사용할 것.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-30
 */
public class AllAllowStrategy extends NormalStrategy{
    public AllAllowStrategy(){
        LogUtil.error("==================================================================", this);
        LogUtil.error(" WARNING: AllAllowStrategy (SSL Unverified) is currently ACTIVE!", this);
        LogUtil.error(" DO NOT USE THIS STRATEGY IN PRODUCTION ENVIRONMENT!", this);
        LogUtil.error("==================================================================", this);
    }

    @Override
    public ClientHttpRequestFactory getFactory() {
        try {
            //-- 모든 인증서를 조건 없이 신뢰(True)하는 TrustManager 배열 생성
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    /**
                     * Not verified certificates.
                     * @param certs the peer certificate chain
                     * @param authType the authentication type based on the client certificate
                     */
                    @SuppressWarnings("java:S4830")
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        //-- Not verified.
                    }
                    @SuppressWarnings("java:S4830")
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        //-- Not verified.
                    }
                }
            };

            //-- SSLContext 초기화 (TLS 프로토콜 사용)
            final SSLContext sslContext = SSLContext.getInstance("TLS");
            // NOSONAR SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            // NOSONAR SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            sslContext.init(null, trustAllCerts, new SecureRandom());

            //-- 호스트네임 검증을 무조건 통과시키는 Verifier 생성
            final HostnameVerifier allHostsAllowVerifier = new HostnameVerifier() {
                @SuppressWarnings("java:S5527")
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    //-- not verified.
                    return true;
                }
            };

            //-- Spring의 SimpleClientHttpRequestFactory를 상속/오버라이드하여 SSL 적용
            SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory() {
                @Override
                protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
                    if (connection instanceof HttpsURLConnection) {
                        HttpsURLConnection httpsConnection = (HttpsURLConnection) connection;
                        httpsConnection.setSSLSocketFactory(sslContext.getSocketFactory());
                        httpsConnection.setHostnameVerifier(allHostsAllowVerifier);
                    }
                    super.prepareConnection(connection, httpMethod);
                }
            };
            factory.setConnectTimeout(connTimeoutMillSec);
            factory.setReadTimeout(readTimeoutMillSec);
            return factory;
        }catch(KeyManagementException | NoSuchAlgorithmException ie){
            LogUtil.error(ie.getLocalizedMessage(), this);
            return null;
        }
    }
}
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
package io.github.sbeholder32167.oidctemplate.rest;

import io.github.sbeholder32167.oidctemplate.rest.strategy.AllAllowStrategy;
import io.github.sbeholder32167.oidctemplate.rest.strategy.RestStrategy;
import io.github.sbeholder32167.oidctemplate.util.LogUtil;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

/**
 * Restful 동작을 담당하는 객체 Class.<br>
 *
 * <p>OIDC 동작에 필수적인 Restful 동작을 담당하는 객체Class.<br>
 * 내부적으로 {@link RestTemplate}을 사용한다.<br>
 * {@link RestTemplate}은 Client에 적용된 Spring Package를 이용한다.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-22
 */
//-- XML Bean 등록
public class RestfulUtil {
    private final RestTemplate restTemplate;
    public RestfulUtil(){
        //-- Default : All Allow Strategy.
        AllAllowStrategy strategy = new AllAllowStrategy();
        // NOSONAR NormalStrategy strategy = new NormalStrategy();
        /* NOSONAR
        MutualSSLStrategy strategy = new MutualSSLStrategy();
        strategy.setTrustStorePath("trustStore.jks");
        strategy.setTrustStorePass("1234321");
        strategy.setKeyStorePath("keyStore.jks");
        strategy.setKeyStorePass("myCertPass");
        */
        strategy.setConnTimeoutMillSec(5000);
        strategy.setReadTimeoutMillSec(5000);
        ClientHttpRequestFactory factory = strategy.getFactory();
        restTemplate = new RestTemplate(factory);
    }
    public RestfulUtil(RestStrategy strategy){
        ClientHttpRequestFactory factory = strategy.getFactory();
        restTemplate = new RestTemplate(factory);
    }

    public <T> ResponseEntity<T> doRestful(String uri, HttpMethod method,
                                           HttpHeaders headers,
                                           Map<String, String> bodyParam,
                                           Class<T> resultCls){
        MultiValueMap<String, String> tempParam = new LinkedMultiValueMap<>();
        if (bodyParam != null){
            for (Map.Entry<String, String> entry : bodyParam.entrySet()){
                tempParam.add(entry.getKey(), entry.getValue());
            }
        }
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(tempParam, headers);
        try{
            return restTemplate.exchange(uri, method, entity, resultCls);
        }catch(HttpClientErrorException | HttpServerErrorException ce){
            LogUtil.error(ce.getLocalizedMessage(), this);
            return new ResponseEntity<>(null, ce.getStatusCode());
        }catch(RestClientException re){
            LogUtil.error(re.getLocalizedMessage(), this);
            return new ResponseEntity<>(null, HttpStatus.SERVICE_UNAVAILABLE);
        }
    }
    public <T> ResponseEntity<T> doRestfulMulti(String uri, HttpMethod method,
                                                HttpHeaders headers,
                                                MultiValueMap<String, String> bodyParam,
                                                Class<T> resultCls){
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(bodyParam, headers);
        try{
            return restTemplate.exchange(uri, method, entity, resultCls);
        }catch(HttpClientErrorException | HttpServerErrorException ce){
            LogUtil.error(ce.getLocalizedMessage(), this);
            return new ResponseEntity<>(null, ce.getStatusCode());
        }catch(RestClientException re){
            LogUtil.error(re.getLocalizedMessage(), this);
            return new ResponseEntity<>(null, HttpStatus.SERVICE_UNAVAILABLE);
        }
    }
}

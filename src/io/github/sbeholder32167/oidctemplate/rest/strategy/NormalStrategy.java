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

import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

/**
 * Default Restful Strategy 구현체 Class.<br>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-22
 */
public class NormalStrategy implements RestStrategy{
    protected int connTimeoutMillSec = 5000;
    protected int readTimeoutMillSec = 5000;

    public void setConnTimeoutMillSec(int connTimeoutMillSec) {
        this.connTimeoutMillSec = connTimeoutMillSec;
    }
    public void setReadTimeoutMillSec(int readTimeoutMillSec) {
        this.readTimeoutMillSec = readTimeoutMillSec;
    }
    @Override
    public ClientHttpRequestFactory getFactory() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(connTimeoutMillSec);
        factory.setReadTimeout(readTimeoutMillSec);
        return factory;
    }
}

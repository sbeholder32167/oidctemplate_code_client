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
package io.github.sbeholder32167.oidctemplate.exception;

/**
 * OIDC Template Code 관련 예외 Class.<br>
 *
 * <p>OIDC Template Code 전반적인 예외 처리 Class.<br>
 * 각 인증 단계 또는 발생 위치를 {@link OIDCExceptionEnum} step으로 관리한다.<br></p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-05-22
 * @see OIDCExceptionEnum
 */
public class OIDCException extends Exception{
    private final OIDCExceptionEnum step;
    public OIDCException(OIDCExceptionEnum step, final String msg){
        super(msg);
        this.step = step;
    }
    public OIDCExceptionEnum getStep(){
        return step;
    }
}

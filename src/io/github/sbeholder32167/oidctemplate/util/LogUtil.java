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

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * 자체 Logging Util.<br>
 *
 * <p>자체적으로 Logging하는 Utility Class.<br>
 * Template Code를 프로젝트에 적용 시 다른 Logger로 변경하여 사용 권장<br>
 * 이 util은 추후 다른 곳으로 Logging Logic을 변경하기 용이하게 할 목적으로 생성함.<br>
 * OIDC Template Code 내부의 모든 Logging은 이곳을 사용 중.</p>
 *
 * @author sbeholder6684
 * @version 1.0.0
 * @since 2026-06-25
 */
public class LogUtil {
    private LogUtil(){}
    @SuppressWarnings("java:S106")
    public static void info(final String message, Object callObj){
        final SimpleDateFormat f = new SimpleDateFormat("HH:mm:ss ");
        String timeStr = f.format(new Date());
        String thrName = Thread.currentThread().getName();
        if (callObj instanceof String){
            System.out.println(timeStr + "[" + thrName + "]" + callObj + ":" + message);
        }else{
            System.out.println(timeStr + "[" + thrName + "]" + callObj.getClass().getName() + ":" + message);
        }
    }
    @SuppressWarnings("java:S106")
    public static void error(final String message, Object callObj){
        final SimpleDateFormat f = new SimpleDateFormat("HH:mm:ss ");
        String timeStr = f.format(new Date());
        String thrName = Thread.currentThread().getName();
        if (callObj instanceof String){
            System.err.println(timeStr + "[" + thrName + "]" + callObj + ":" + message);
        }else{
            System.err.println(timeStr + "[" + thrName + "]" + callObj.getClass().getName() + ":" + message);
        }
    }
}
[한국어](./README_KR.md) | [English](./README.md)

# OIDC Template Code - Client

본 Template Code는 **JDK 7 이상, Spring 4.x 이상, Egov 3.6 이상**의 Legacy Spring 기반 Application에서 **Keycloak 등 OIDC 인증** 연동을 수월하고 신속하게 지원할 목적으로 개발되었습니다.

의존성 지옥을 우회하기 위해 Template Code 형태로 제공되며, `src` 디렉토리 내의 패키지 파일들을 귀사 Application의 소스 폴더에 복사하는 방식으로 적용을 시작하실 수 있습니다.

---

## 📋 목차
- [주요 특징](#-주요-특징)
- [연동 절차](#-연동-절차)
- [기술 사양 및 의존성](#-기술-사양-및-의존성)
- [주의사항](#-주의사항)
- [라이선스](#-라이선스)
- [문의](#-문의)

---

## ✨ 주요 특징
- **Filter / Controller 방식 선택 제공**:
    - **Custom Filter 방식**: Custom Filter, Provider, AuthSuccessHandler 조합(Spring Security 사용 여부에 따라 구성 가능).
    - **Controller Template 방식**: 인증 로직이 Controller Endpoint로 구현되어, Filter 적용이 어려운 환경에서 사용 가능.
- **침습 최소화**: 기존 인증 로직을 건드리지 않고, Custom 인증 로직을 '추가'하는 방식으로 설계되었습니다.
- **Boilerplate 코드 제공**: Jar 배포 방식이 아닌 소스 코드 제공 방식으로, 환경에 맞춰 유연하게 수정 및 통합이 가능합니다.
- **추상화된 Adapter 인터페이스**: 세션 핸들링, 로그인/로그아웃 후속 처리 등 커스터마이징이 필수인 부분을 인터페이스로 분리하였습니다.
- **유연한 세션 관리**: 기본 LocalMap 구현체 제공 및 클러스터링 환경을 위한 Redis/ehCache 등 세션 공유 저장소로 교체 가능.

---

## 🚀 연동 절차
1. **소스 복사**: `src` 디렉토리 내의 패키지 파일들(`io.github`)을 귀사 Application 소스 폴더로 복사합니다.
    - 만약 Spring Security가 적용 대상 Application에 존재하지 않는다면, 복사된 파일들 중에서 i.g.s.oidctemplate.client.security 패키지와 i.g.s.oidctemplate.egov 패키지를 삭제하세요. 
2. **Adapter 구현**: 제공되는 **5종의 Adapter Interface**를 구현합니다.
    - **토큰 처리**: 토큰을 수신하여 Legacy Session에 반영. (i.g.s.oidctemplate.adapter.ClientAuthConvertAdapter)
    - **인증 후속 처리**: 로그인 성공 및 실패(세션 중복 등) 시 동작.(i.g.s.oidctemplate.adapter.ClientLoginAdapter)
    - **로그아웃 처리**: Keycloak IDP와의 동시 로그아웃 직전/직후 동작. (i.g.s.oidctemplate.adapter.ClientLogoutAdapter)
    - **세션 핸들링**: Legacy Session을 Template Code에서 핸들링. (i.g.s.oidctemplate.adapter.ClientLegacySessionAdapter)
    - **예외 처리**: 인증 Flow 도중 발생하는 예외에 대한 동작. (i.g.s.oidctemplate.exception.OIDCExceptionHandler)
3. **설정 파일 복사**: `setting_sample` 디렉토리의 `sample_oidc-config.xml` 예제를 설정 폴더로 복사합니다.
    - 적용 대상 어플리케이션 파일명 형식에 따라 파일명의 변경이 필요할수도 있습니다.
    - Spring Security Package가 적용 대상 Application에 존재할 경우, `setting_sample/security` 디렉토리의 `sample_oidc-config.xml`를 사용합니다
    - Spring Security Package가 적용 대상 Application에 없다면, `setting_sample/non-security` 디렉토리의 `sample_oidc-config.xml`를 사용합니다
4. **Bean 적용**: 구현한 5종의 Adapter Class를 `sample_oidc-config.xml`에 등록합니다. (in CUSTOMIZING AREA.)
5. **Spring Security 설정 변경**:
    - `OIDCLoginFilter` 인증 시작 및 Redirect URI를 `permitAll`로 설정.
    - `OIDCLogoutFilter` 로그아웃 URI에 대한 CSRF 우회 설정 추가.
    - 이 항의 내용은 Spring Security Package를 사용할 경우에 한합니다
    - `sample_security-config.xml` 을 참조하시기 바랍니다
6. **환경 설정**: `sample_oidc-config.xml` 내 Keycloak URI, Client ID, Client Secret, 예외 리다이렉트 URI 등을 환경에 맞게 수정합니다.
7. **빌드 및 테스트**: 빌드 후 인증 흐름을 확인합니다.

- *구현 예제 참조: https://github.com/sbeholder32167/egov_sample_with_oidctemplate_code_client*

#### ※ 연동 절차에 대해서는 추후 더욱 자세한 내용을 담은 별도 파일로 설명해 드릴 예정입니다.

---

## 🛠 기술 사양 및 의존성
- **지원 환경**: JDK 7+, Spring 4.x+, Egov 3.6+
- **인증 방식**: Standard Flow
- **필수 의존성**: `com.auth0:java-jwt`
- **선택적 의존성**: Redis 또는 ehCache 등 세션 공유 구현체 사용 시 추가 필요

---

## ⚠️ 주의사항
- 본 코드는 **Spring Security OAuth Client를 대체하는 솔루션이 아닙니다.**
- Spring Security OAuth Client를 사용할 수 있는 환경이라면, Spring Security OAuth Client의 사용을 권장합니다.
- 본 코드는, **Spring Security OAuth Client의 사용이 곤란한 환경의 레거시 Application**일지라도, **Keycloak과 연동하여 공격 표면을 줄이기 위한 목적**에 도움이 되고자 만들어졌습니다.
- 본 Template Code의 내용은 예고 없이 변경될 수 있습니다

---

## 📄 라이선스
- 이 프로젝트는 **Apache 2.0 라이선스**를 따릅니다.

---

## 📧 문의
- **Email**: sbeholder6684@gmail.com (유료 기술 자문(지원) 문의)
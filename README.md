[English](./README.md) | [한국어](./README_KR.md)

# OIDC Template Code - Client

This template code is designed to facilitate quick and easy integration of **OIDC (OpenID Connect) authentication**, such as Keycloak, into **Legacy Spring-based applications** (JDK 7+, Spring 4.x+, Egov. framework (in South Korea) 3.6+).

To avoid "dependency hell," this code is provided as **Template source code**. You can begin integration by copying the package files located in the `src` directory directly into your application's source folder.

---

## 📋 Table of Contents
- [Key Features](#-key-features)
- [Integration Steps](#-integration-steps)
- [Technical Specifications & Dependencies](#-technical-specifications--dependencies)
- [Important Notes](#-important-notes)
- [License](#-license)
- [Support](#-paid-technical-support)

---

## ✨ Key Features
- **Flexible Authentication Methods**:
    - **Custom Filter Approach**: Combines Custom Filter, Provider, and AuthSuccessHandler (compatible with or without Spring Security).
    - **Controller Template Approach**: Authentication logic is implemented as a Controller endpoint, ideal for environments where a Filter-based approach is difficult to implement.
- **Minimal Intrusion**: Designed to 'add' custom authentication logic rather than modifying existing logic, ensuring minimal impact on legacy systems.
- **Template Source Code**: Delivered as source code rather than a Jar package, allowing for flexible modification and seamless integration into your specific environment.
- **Abstracted Adapter Interfaces**: Key areas requiring customization—such as session handling, post-login/logout processing, and exception handling—are defined as interfaces.
- **Flexible Session Management**: Comes with a default `LocalMap` implementation, with the ability to switch to clustered storage (e.g., Redis, ehCache) by implementing the registry/repository.

---

## 🚀 Integration Steps
1. **Copy Source**: Copy the package files (including `io.github`) from the `src` directory into your application's source folder.
    - If Spring Security does not exist in the application to which it is applied, delete the i.g.s.oidctemplate.client.security and i.g.s.oidctemplate.egov packages from the copied files.
2. **Implement Adapters**: Implement the **5 provided Adapter Interfaces**:
    - **Token Handling**: Process tokens and reflect them in your legacy session. (i.g.s.oidctemplate.adapter.ClientAuthConvertAdapter)
    - **Post Authentication Handling**: Handle logic for login success/failures (e.g., duplicate sessions). (i.g.s.oidctemplate.adapter.ClientLoginAdapter)
    - **Logout**: Handle pre- and post-logout actions in coordination with the Keycloak IDP. (i.g.s.oidctemplate.adapter.ClientLogoutAdapter)
    - **Session Handling**: Manage legacy sessions within the template code. (i.g.s.oidctemplate.adapter.ClientLegacySessionAdapter)
    - **Exception Handling**: Define behaviors for exceptions during the authentication flow. (i.g.s.oidctemplate.exception.OIDCExceptionHandler)
3. **Copy Configuration XML file**: Copy the `sample_oidc-config.xml` sample from the `setting_sample` directory to your application's config folder.
    - Changing name of the file may be required according to config file name format in your application.
    - If the Spring Security Package exists in the target application, use `sample_oidc-config.xml` in the `setting_sample/security` directory.
    - If the Spring Security Package does not exist in the target application, use `sample_oidc-config.xml` in the `setting_sample/non-security` directory.
4. **Register Beans**: Apply your implemented 5 Adapter classes to section named 'CUSTOMIZING AREA' in `sample_oidc-config.xml`.
5. **Spring Security Configuration**:
    - Set `OIDCLoginFilter` start and redirect URIs to `permitAll`.
    - Add CSRF bypass settings for the `OIDCLogoutFilter` logout URI.
6. **Environment Setup**: Configure Keycloak URIs, Client ID, Client Secret, and redirect URIs in `sample_oidc-config.xml`.
7. **Build & Test**: Build your application and verify the authentication flow.

- *Implementation Example: https://github.com/sbeholder32167/egov_sample_with_oidctemplate_code_client*

---

## 🛠 Technical Specifications & Dependencies
- **Supported Environment**: JDK 7+, Spring 4.x+, Egov. framework (in South Korea) 3.6+
- **Authentication Flow**: Standard Flow
- **Required Dependencies**: `com.auth0:java-jwt`
- **Optional Dependencies**: Additional libraries may be required if implementing external session storage like Redis or ehCache.

---

## ⚠️ Important Notes
- This code is **not a replacement for Spring Security OAuth Client**.
- If your environment supports Spring Security OAuth Client package, we highly recommend using 'Spring Security OAuth Client Package'.
- This template is intended as a bridge to reduce the attack surface by integrating Keycloak in legacy environments where standard Spring Security OAuth Client libraries are difficult to deploy.
- The contents of this template code are subject to change without notice.

---

## 📄 License
- This project is licensed under the **Apache 2.0 License**.

---

## 📧 Paid Technical Support
- **Email**: sbeholder6684@gmail.com (in South Korea only.)
---

title: Estonian Internet Foundation's eeID Documentation

toc_footers:
   - <a href='https://internet.ee'>Estonian Internet Foundation</a>
   - <a href='https://github.com/internetee/eeID-manager'>Sign Up for eeID</a>
   - <a href='https://github.com/slatedocs/slate'>Powered by Slate</a>
includes:

search: true
code_clipboard: true
---

# Introduction

Welcome to the Estonian Internet Foundation's eeID documentation! This document describes the technical characteristics of the Estonian Internet Foundation eeID authentication service and includes advice for interfacing the client application with e-services. The eeID authentication service can be used by institutions and private persons to add the support of various different [authentication methods](#authentication-methods) to its e-service:

- Mobiil-ID
- ID card
- Smart-ID
- EU-citizen cross-border authentication (i.e. via eIDAS-Node)
- FIDO2 Web Authentication (WebAuthn)

# OpenID Connect

The eeID authentication service is based on the OpenID Connect protocol, which is built on top of the OAuth 2.0 authorization framework. It's designed to provide a secure and standardized way to authenticate users and obtain their basic profile information. OIDC is commonly used in applications that require user authentication, such as web and mobile applications.

Limited subset from standards was chosen and some adjustments were made. The main selections and adjustments compared to the full OpenID Connect protocol are the following:

- The service supports the authorisation code flow. The authorisation code flow is deemed the most secure option and is thus appropriate for public services.
- All information about an authenticated user is transferred to the application in an ID token.
- The eIDAS assurance level is also transferred to the application if it is known (in the acr statement).
- The authentication method is selected by the user in the authentication service or by the interfaced client with the scope parameter.
- Cross-border authentication based on the technical specification of eIDAS.
- Dynamic registration of the client application is not supported. The client application is registered in [eeID manager](https://eeid.ee) by a separate procedure.

# Getting started

In order to get started you have to sign up and create your first client (service) in the [eeID manager](https://eeid.ee). 

1. Add a new contact first. From the main menu select `Contacts` to go to the contacts management view. Click on + Create New Contact and fill in the form.
![Create New Contact](images/new_contact_form.png)

2. From the main menu select `Services` to go to the service management view. Click on + Create New Service.
![Create New Service](images/create_new_service.png)

3. Fill in the form
![New Service Form](images/new_service_form.png)

4. All the fields must be valid to proceed.

* Name - enter the name for your service. This will ultimately appear in-front of your customers
* Description - provide a brief description of your service. It should be concise, ideally one sentence.
* Approval description - in this field, provide details about what you are building and who your target customers are.
* Redirection URL - specify the URL where users should be redirected to after they have been authenticated. If you do not know what you will use, just enter `https://localhost/callback` for now. The value can be changed later if needed.
* Environment - indicate the environment in which you will be using the service. `Test` is free and used for testing purposes.
* Authentication methods - choose the authentication methods you wish to support. The options given are `EE ID-card`, `Mobile-ID`, `Smart-ID`, `EU-Citizen` and `Webauthn`. You can select one or more methods based on your preference.
* Contact - choose an existing contact or create a new one. This contact will be associated with the service, and it might be the point of contact for any communications or notifications regarding the service.
* Submission - review all the details entered in the form, and if everything is correct, click on `SUBMIT FOR APPROVAL` to submit your service.

Once you submit the form, it will be reviewed by the service administrators
at the [Estonian Internet Foundation](https://www.internet.ee/)
They will assess the details provided in your application to ensure
they meet the necessary criteria and adhere to the [terms of use](https://meedia.internet.ee/files/Terms_of_use_eeID.pdf).
If your application meets all the requirements, it will be approved and you will be provided with the client ID and secret.
In case there are issues or discrepancies in your application, it might be rejected.
After the review process is completed, you will receive a notification regarding the
status of your application. This notification will inform you whether your application has
been approved or rejected.

# Authentication methods

By default, the eeID service facilitates the following authentication methods:

* `EE ID-card` - [Estonian ID-card](https://www.id.ee/en/rubriik/id-card-en/)
* `Mobile-ID` - [Estonian Mobile-ID](https://www.id.ee/en/mobile-id/) (also used in Lithuania)
* `Smart-ID` - [Estonian Smart-ID](https://www.id.ee/en/article/smart-id/) (also used in Latvia and Lithuania)

These authentication methods stand as testimony to Estonia's advanced digital infrastructure, offering citizens secure, reliable, and convenient options for online authentication. By leveraging state-of-the-art technology and stringent security protocols, these methods ensure that Estonian citizens can safely access e-services, conduct online transactions, and sign digital documents from the comfort of their homes or on the go.

* `EU-Citizen` authentication method activates a range of cross-border authentication methods. This activation allows EU citizens to log in to e-services using authentication methods recognized and approved in their respective EU member states (i.e. via [eIDAS-Node](https://ec.europa.eu/digital-building-blocks/wikis/display/DIGITAL/eIDAS-Node+Integration+Package)):

Country     | Authentication methods | Required scopes
------------| ----------------------| ---------------
Belgium | eIDAS | `eidas`
Czech Republic | mojeID | `eidas`
Estonia | ID-card, Mobile-ID, Smart-ID | `eidas` `idcard` `mid` `smartid`
Latvia | Smart-ID | `eidas` `smartid`
Lithuania | Smart-ID, Mobile-ID | `eidas` `smartid` `mid`
Portugal | eIDAS | `eidas`
Sweden | eIDAS | `eidas`

* `Webauthn` authentication method enables a robust and secure user authentication process grounded
in public key cryptography. This method does away with the need for passwords,
instead allowing users to employ local authenticators such as biometrics or 
security keys to securely and conveniently access online services.
Being a core component of the [FIDO Alliance's FIDO2](https://fidoalliance.org/fido2-2/fido2-web-authentication-webauthn/) set of specifications,
it is designed to foster stronger and simpler web authentication mechanisms,
enhancing security and user experience in the digital landscape.

For a demo of WebAuthn, visit [https://webauthn.io/](https://webauthn.io/).

<b>Creating a WebAuthn Credential through eeID:</b>

1. <b>Initial Authentication</b>
<br>Before creating a WebAuthn credential, the users must first authenticate themselves
using one of the other methods provided in the eeID service. This step ensures that the user's identity
is verified through a secure and recognized authentication method.

2. <b>eeID as Identity Provider</b>
<br>Once the initial authentication is successful, the eeID service acts as an identity provider.
In this role, it verifies and stores the authenticated data, establishing a secure and
trusted identity framework for the user.

3. <b>Creating the Webtuhn Credential</b>
<br>Following the successful authentication through eeID,
the user can proceed to create a WebAuthn credential. This process involves:
    * <b>Registering a Local Authenticator.</b> The user will register a local authenticator,
    such as a biometric identifier (fingerprint, facial recognition, etc.) or a security key.
    * <b>Public Key Cryptography.</b> The WebAuthn method leverages public key cryptography,
    where a private key is stored on the user's local device, and a public key is
    stored on the server. This setup ensures a secure and password-less authentication process.
    * <b>Credential ID.</b> Upon successful registration, a unique Credential ID is generated, which will be used for future authentications.

4. <b>Future Authentications</b>
<br>With the WebAuthn credential created, the user can now use this method for future authentications. When logging in:
    * The user will be prompted to authenticate using their local authenticator.
    * The server verifies the authentication using the stored public key, ensuring a secure and swift login process.

Creating a WebAuthn credential through the eeID service not only enhances the security of
online transactions but also offers a user-friendly authentication experience.
It represents a forward step in secure, password-less digital authentication,
promoting ease of use without compromising on security.

# Requests

## Authentication request

An authentication request is a HTTP GET request by which the user is redirected from the client application to the eeID server for authentication.

URL: `https://auth.eeid.ee/hydra-public/oauth2/auth`

Required query parameters:

- `client_id` - service identifier issued upon registration of the client application in eeID portal
- `state` - security code against false request attacks (cross-site request forgery CSRF)
- `redirect_uri` - redirect_uri
- `response_type` - determines the manner of communication of the authentication result to the server, must be equal to `code`
- `scope` - authentication scopes, `openid` is compulsory (required by the OpenID Connect protocol). The following scopes are supported: `idcard`, `mid`, `smartid`, `eidas` and `webauthn`. The scopes must correspond to the authentication methods selected while registering the service:

Scope      | Authentication method
-----------| --------------
`idcard` | EE ID-card
`mid` | Mobile-ID
`smartid` | Smart-ID
`eidas` | EU-Citizen
`webauthn` | Webauthn

Optional query parameters:

- `ui_locales` - selection of the user interface language. The following languages are supported: `et`, `en`, `ru`
- `nonce` - unique parameter which helps to prevent replay attacks based on the protocol

An example of an authentication request:

```shell
HTTP GET https://auth.eeid.ee/hydra-public/oauth2/auth?client_id=oidc-b8ab3705-c25f-4271-b87d-ecf190aa4982-11
&redirect_uri=https%3A%2F%2Feservice.institution.ee%2Fcallback
&response_type=code
&scope=openid%20idcard%20mid%20smartid%20eidas
&state=f3b2c3e7f4cf0bed3a783ed6ece617e3
```

## Redirect request

The redirect request is a HTTP GET request which is used to redirect the user back to the return address entered upon registration of the client application in [eeID manager](https://eeid.ee). In the redirect request an authorization code is sent to the client application, based on which the client application will request the access token in order to get personal identification code, name and other attributes of the authenticated person. The security code state received in the authentication request is mirrored back. Read more about forming and verifying state from [Protection against false request attacks](#protection).

An example of a redirect request:

```shell
HTTP GET https://eservice.institution.ee/callback?code=71ed5797c3d957817d31&
state=OFfVLKu0kNbJ2EZk
```
<br>
Request might contain other URL parameters, that client application must ignore.

If eeID is unable to process an authentication request - there will be an error in the request. eeID transfers an error message (URL parameter `error`) and the description of the error (URL parameter `error_description`) in the redirect request:

```shell
HTTP GET https://eservice.institution.ee/callback?error=invalid_scope&error_description=
The+requested+scope+is+invalid%2C+unknown%2C+or+malformed.+The+OAuth+2.0+Client+is+not+allowed+to+request+scope+%27invalid_scope%27.
&state=0b60fe50138f8fdd56afd2a6ab7a40f9
```
<br>
The redirect request errors are normally resulted by a misconfiguration; therefore the error description in parameter `error_description` is not needed to be displayed for the user directly. The client application should check whether or not an error message has been sent.

## Identity token request

The identity token request is an HTTP POST request which is used by the client application to request the identity token from the login server of eeID.

An example of an identity token request:

```shell
HTTP POST https://auth.eeid.ee/hydra-public/oauth2/token
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content_Type: application/x-www-form-urlencoded
```

```shell
grant_type=authorization_code&
code=71ed5797c3d957817d31&
redirect_uri=https%3A%2F%2Feservice.institution.ee%2Fcallback
```
<br>
The client secret code must be provided in the identity token request. For this purpose, the request must include the `Authorization` request header with the value formed of the word Basic, a space and a string `<client_id>:<client_secret>` encoded in the Base64 format. The body of the HTTP POST request must be presented in a serialised [format](https://openid.net/specs/openid-connect-core-1_0.html#FormSerialization) based on the OpenID Connect protocol. The body of the request must include the `code` received from the authentication service.

The body of the request must include the following parameters:

Element        | Description
-------------- | --------------
`grant_type` | The `authorization_code` value required based on the protocol
`code` | The authorization code received from the authentication service
`redirect_url`| The redirect URL sent in the authorisation request

The server verifies that the access token is requested by the right application and issues the access token included in the response body. The response body uses JSON format consisting four elements:

Element        | Description
-------------- | --------------
`access_token` | OAuth 2.0 access certificate. With access token the client application can issue authenticated user’s data from `userinfo` endpoint.
`token_type` | OAuth 2.0 access token type with bearer value
`expires_in`| The validity period of the OAuth 2.0 access token
`id_token` | Identity token. Presented in [JWS Compact Serialization](https://tools.ietf.org/html/rfc7515#section-3.1) form

Response body might contain other fields, that client application must ignore. The identity token is a certificate of the fact of authentication issued by eeID. The identity token is issued in [JSON Web Token](https://jwt.io/), JWT format. The identity token is always [signed](https://tools.ietf.org/html/rfc7515#section-5.2).

The client application must obtain the identity token immediately or within 30 seconds (before the expiry time of the identity token).

## User info request

User info request enables requesting information about an authenticated user based on a valid OAuth 2.0 access token. The request must be done by using the HTTP GET method. The access token must be presented to the user info endpoint in the HTTP header by using [the Bearer Token method](https://tools.ietf.org/html/rfc6750#section-2.1) or as a [URLi parameter](https://tools.ietf.org/html/rfc6750#section-2.3).

Example 1 - transferring an access certificate in the `Authorization` header:

```shell
HTTP GET https://auth.eeid.ee/hydra-public/userinfo
Auhtorization: Bearer AT-20-qWuioSEtFhYVdW89JJ4yWvtI5SaNWep0
```
<br>
Example 2 – transferring of access certificate as an `access_token` parameter:

```shell
HTTP GET https://auth.eeid.ee/hydra-public/userinfo?access_token=AT-20-qWuioSEtFhYVdW89JJ4yWvtI5SaNWep0
```
<br>
The valid access token response is provided in the JSON format. Example:

```json
{
   "acr": "high",
   "amr": [
      "smartid"
   ],
   "profile_attributes": {
      "authentication_type": "SMART_ID",
      "date_of_birth": "2000-01-01",
      "family_name": "O’CONNEŽ-ŠUSLIK TESTNUMBER",
      "given_name": "MARY ÄNN",
   },
   "sub": "EE60001019906",
   "auth_time": 1694591147,
   "state": "2093077beb6d063ea65e61fa4c9b2814"
}
```
<br>
The claims included in the response are issued based on the identity token.

| JSON element (claim)        | Description
| --------------------------- | ----------------
| `auth_time` | The time of successful authentication of the user.
| `sub` | The identifier of the authenticated user (personal identification code or eIDAS identifier) with the prefix of the country code of the citizen (country codes based on [the ISO 3166-1 alpha-2 standard](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2#:~:text=ISO%203166%2D1%20alpha%2D2%20codes%20are%20two%2Dletter,special%20areas%20of%20geographical%20interest.)).
| `amr` | The authentication method used for user authentication. Example values: `mID` - Mobile-ID, `idcard` - Estonian ID card, `smartid` - Smart-ID.
| `state` | The authentication request’s state parameter value.
| `acr` | `high` - level of authentication based on the eIDAS LoA (level of assurance). Possible values: `low`, `substantial`, `high`.
| `aud` | The ID of a client application that requested authentication.
| `iat` | The time of issue of the certificate (in Unix epoch format).
| `iss` | Issuer of the certificate.
| `profile_attributes` | Data of the authenticated user, including the eIDAS attributes
| `profile_attributes.date_of_birth` | The date of birth of the authenticated user in the ISO_8601 format.
| `profile_attributes.given_name` | The first name of the authenticated user.
| `profile_attributes.family_name` | The surname of the authenticated user.

Response body might contain other fields, that client application may ignore.

In case the access token presented to the user information endpoint is missing or is expired, an error code and a brief description 
about the error are returned:

```json
{
   "error": "invalid_token",
   "error_description": "Token expired. Access token expired at '2022-10-07 14:55:34 +0000 UTC'."
}
```

# Protection

The client application must implement protective measures against false request attacks (cross-site request forgery, CSRF). 
This can be achieved by using `state` security code. Using `state` is compulsory.

Using `state` with a cookie set on the client application side means that the client application itself does not have to remember the state parameter value. The process is described below.

The `state` security code is used to combat falsification of the redirect request following the authentication request. 
The client application must perform the following steps:

1. Generate a random hexadecimal state session key, for example of the length of 32 characters: `07f19702e7e9591c6fa2554e1fcf5f4a` (referred to as `R`).
2. Add an order to set a cookie for the client application domain with a value of R immediately before making the authentication request, for example:

`Set-Cookie ESERVICE=07f19702e7e9591c6fa2554e1fcf5f4a; HttpOnly`
Where `ESERVICE` is a freely selected cookie name. The `HttpOnly` attribute must be applied to the cookie.

3. Set the following value, in the authentication request, for the `state` parameter calculated based on section 1:

```shell
state=07f19702e7e9591c6fa2554e1fcf5f4a
```
<br>
Length of state parameter must be minimally 8 characters. In the course of processing the redirect request, the client application must:

4. Take the `ESERVICE` value of the cookie received with the request.
5. Verify that the `ESERVICE` value matches the state value mirrored back in the redirect request.

The redirect request may only be accepted if the checks described above are successful. 
The key element of the process described above is connection of the `state` value with the session. This is achieved by using a cookie.

# Endpoints and timeouts

### Production service

| Endpoint         | URL 
| ---------------- | ----------------
| server discovery | https://auth.eeid.ee/hydra-public/.well-known/openid-configuration 
| public signature key | https://auth.eeid.ee/hydra-public/.well-known/jwks.json 
| authorization | https://auth.eeid.ee/hydra-public/oauth2/auth 
| token | https://auth.eeid.ee/hydra-public/oauth2/token 
| userinfo | https://auth.eeid.ee/hydra-public/userinfo 

### Test service

| Endpoint         | URL 
| ---------------- | ----------------
| server discovery | https://test-auth.eeid.ee/hydra-public/.well-known/openid-configuration
| public signature key | https://test-auth.eeid.ee/hydra-public/.well-known/jwks.json
| authorization | https://test-auth.eeid.ee/hydra-public/oauth2/auth
| token | https://test-auth.eeid.ee/hydra-public/oauth2/token
| userinfo | https://test-auth.eeid.ee/hydra-public/userinfo

### Timeouts

| Timeout                      | Value           | Remark
| ---------------------------- | --------------- | ---------------------------------------------
| session | 30 min | eeID server creates a session with the user identified. If the user doesn’t perform any activity on eeID page, the session will expire in 30 minutes. Note: eeID session must be distinguished from the session between the client application and the user.
| SSL/TLS handshake | 25 s | In case of ID-card authentication. The user must enter PIN1 within 25 seconds. After the timeout, the authentication will be terminated for security reasons.
| Authorization code | 30 s | The client application must obtain the access token using authorization code within 30 seconds.

# Testing

A prerequisite for testing the eeID authentication service is registering a service in test environment. After approving your service, it is possible to test the service immediately, using the credentials generated after approving.

Users for successful authentication:

- Mobile ID phone and id numbers: EE - `00000766` | `60001019906`, LT - `60000666` | `50001018865`
- Smart-ID personal codes: EE - `30303039914`, LV - `030303-10012`, LT - `30303039914`
- eIDAS country Czech Republic: select `Testovací profily` from the redirection screen and select a test user for authentication

### Mobile ID

The eeID test environment is directed to the Mobiil-ID demo environment. Public test numbers are available for use:

* Test numbers are available [here](https://github.com/SK-EID/MID/wiki/Test-number-for-automated-testing-in-DEMO). Apply only Estonian (EE) test numbers and personal identification codes.

### Smart ID

The eeID test environment is directed to the Smart-ID demo environment. There are two options for use:

* Install the Smart-ID demo application on your device and register a [demo account](https://github.com/SK-EID/smart-id-documentation/wiki/Smart-ID-demo#getting-started).
* Use [test users](https://github.com/SK-EID/smart-id-documentation/wiki/Environment-technical-parameters#test-accounts-for-automated-testing).

# Code examples

## OpenID Connect Client with Spring Security

One of the key features of Spring Security 5 was the native support for OAuth2 and OIDC.
Making use of the OIDC configuration information (OIDC metadata), integrating with
the eeID Server gets super easy. This tutorial shows how to use a registered service to login via eeID and access the user details within an ID-token.

### Prerequisites

You should be familiar with Java, Spring Boot, and Spring Security.
Optionally, you should know how to use IntelliJ IDEA, but you can use any IDE of your choice.
Make sure you [configure a service](#getting-started) in the [eeID manager](https://eeid.ee) before getting started.

### Setting up the project

1. Visit [start.spring.io](https://start.spring.io/) to create a new Spring Boot project
2. Select Maven as your build tool and Java as your language
3. Change the group to something meaningful and name your project
4. Choose JDK 17 (or the latest available)
5. Search for and add the following dependencies: Spring Security, OAuth2 Client, Spring Reactive Web, Thymeleaf

![Spring Initializr](images/spring_initializr.png)
6. Generate the application. Spring Initializr creates an archive with a bootstrap application that includes the selected dependencies. Download and extract the archive, and import the project in an IDE of your choice

### Add a Starting Site

Provide a starting site that is publicly available. Create the file `src/main/resources/templates/index.html`.
Add a link to the protected resource `/secured`.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Spring Boot eeID Demo</title>
</head>

<body>
<h1>Welcome</h1>
<p><a href="/secured">Secured content</a></p>
</body>
</html>
```

### Add a Controller

When the user logs in show the username. For that create a controller that handles
requests for the endpoint `/` and `/secured`. Create the file `src/main/java/com/example/demo/UserController.java`:

```java
@Controller
public class UserController {
    @GetMapping("/")
    public String index(){
        return "index";
    }

    @GetMapping("/secured")
    public String user(Model model,
                        @AuthenticationPrincipal OidcUser oidcUser) {
        model.addAttribute("userName", oidcUser.getName());
        model.addAttribute("audience", oidcUser.getAudience());
        return "secured";
    }
}
```
<br>
Create a template called `secured.html` next to `index.html`. Output the attributes for the username and client ID.

```html
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<title>Spring Boot eeID Demo - Login</title>
	<meta charset="utf-8" />
</head>
<body>

<h1>Your Login Details</h1>
<div>
	Welcome <span style="font-weight:bold" th:text="${userName}"/>!
	You logged in at the OAuth 2.0 Client <span style="font-weight:bold" th:text="${audience}"/>.
</div>
</body>
</html>
```
<br>
With these routes in place, we can now set up our security configuration.

### Protect the User Area

So far there are two unprotected endpoints: `/` and `/secured`.
Create another class, that enforces OAuth for certain paths. Create the file `src/main/java/com/example/demo/OAuth2SecurityConfig.java` with the following content:

```java
@Configuration
@EnableWebFluxSecurity
public class OAuth2SecurityConfig {

	@Bean
	public SecurityWebFilterChain filterChain(ServerHttpSecurity http) throws Exception {
		http
			.authorizeExchange(authorize -> authorize
				.pathMatchers("/", "/error").permitAll()
				.anyExchange().authenticated()
			)
			.oauth2Login(oauth2 -> oauth2
				.authenticationMatcher(new PathPatternParserServerWebExchangeMatcher("/login/oauth2/callback/{registrationId}"))
			);
		return http.build();
	}
}
```
<br>
This enables and configures Spring Web Security.
The endpoints `/` and `/error` are public. Any other requests must be authenticated using OAuth.
Spring Security creates a default login page at `/login` that lists all the login options. 

### Configure the OAuth Client

Define the following client in `src/main/resources/application.yml`:

```yml
spring:
  main:
    allow-bean-definition-overriding: true
  application:
    name: demo
  security:
    oauth2:
      client:
        registration:
          eeid:
            client-name: Login with the eeID
            client-id: <your-eeid-client-id>
            client-secret: <your-eeid-secret>
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/callback/{registrationId}"
            scope: openid,idcard,mid,smartid,eidas
        provider:
          eeid:
            issuer-uri: https://test-auth.eeid.ee/hydra-public/
```
<br>
This triggers Spring Boot to register a client. The client registration gets the id `eeid` which is part of the (default) `redirect-uri`.
The remaining properties, `client-id`, `client-secret` and `scope` have been defined when
configuring the client in the [eeID manager](https://eeid.ee) (see [Getting Started](#getting-started)).
You can choose any descriptive `client-name`. This is the string that is used in the default
login page setup at `/login`.
<br>
Spring Boot Security loads all the necessary OpenID configuration from the metadata
at [https://test-auth.eeid.ee/hydra-public/.well-known/openid-configuration](https://test-auth.eeid.ee/hydra-public/.well-known/openid-configuration)
and ensures that the user-agent gets redirected to the right endpoints for authentication.

### Run the Demo Application

Start the demo application with `mvn spring-boot:run`. Navigate to `http://localhost:8080` to access the index site.
Click on the link to access `http://localhost:8080/secured` that triggers a login.

![Login Screen](images/login_screen.png)
<br>
After successful login the page shows details retrieved from the ID token.

![Login Details](images/login_details.png)
<br>
You can also navigate to `http://localhost:8080/login` to directly access the default login page created by Spring Security.

For further examples and help regarding OAuth2 and Spring Security for a reactive web application visit [Spring Security Reference Documentation](https://docs.spring.io/spring-security/reference/reactive/oauth2/login/index.html).

## PHP OpenID Connect example

Make sure you [configure a service](#getting-started) in the [eeID manager](https://eeid.ee) before getting started.
<br>
This example uses the jumbojett basic OpenID Connect client and phpdotenv installed using composer and running on Docker container.

* jumbojett: [https://github.com/jumbojett/OpenID-Connect-PHP](https://github.com/jumbojett/OpenID-Connect-PHP)
* phpdotenv: [https://github.com/vlucas/phpdotenv](https://github.com/vlucas/phpdotenv)
* composer: [https://getcomposer.org/](https://getcomposer.org/)

It takes users to an attributes page after login and display the claims/values that have been passed.
In the real world you would read the claims and feed them into your authorisation/user-session management process.

### Instructions

1. Start by creating a new Dockerfile. This file will be used to build an image for your container. In the Dockerfile, include the following lines::

```dockerfile
FROM php:7.4-apache
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf
RUN apt-get update && apt-get install -y \
    zip \
    unzip
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
```
<br>
This will use the `php:7.4-apache` image as the base for your container and install the necessary
dependencies for Composer (zip and unzip). It will then use curl to download the Composer
installer and run it to install Composer in the `/usr/local/bin` directory.
<br>
<br>
2. Create docker-compose.yml file in your project folder:

```yml
version: '3.1'

services:
  app:
    build:
      context: .
    ports:
      - "8082:80"
    volumes:
      - .:/var/www/html
    environment:
      - APACHE_DOCUMENT_ROOT=/var/www/html
```
<br>
3. Create composer.json

```json
{
    "require": {
        "jumbojett/openid-connect-php": "0.8.0",
        "vlucas/phpdotenv": "^5.3"
    }
}
```
<br>
4. Build the image and run a new container

```shell
dockder-compose up --build
```
<br>
5. Run composer to read the composer.json file from the current directory, resolve the dependencies and install them into vendor:

```shell
docker-compose run --rm app composer install
```
<br>
6. Create a php page to handle the login, e.g. `index.php`.
This one creates a session attribute of an array of the returned claims and then passes the user
to an `attributes.php` page where they can be displayed.

```php
<?php

require 'vendor/autoload.php';

use Jumbojett\OpenIDConnectClient;

$dotenv = \Dotenv\Dotenv::createUnsafeImmutable(__DIR__);
$dotenv->load();

$issuer = getenv('ISSUER');
$cid = getenv('OAUTH_CLIENT_ID');
$secret = getenv('OAUTH_CLIENT_SECRET');
$redirectUrl = getenv('CLIENT_REDIRECT_URI');
$scope = getenv('SCOPE');

$oidc = new OpenIDConnectClient($issuer, $cid, $secret);
$oidc->setRedirectURL($redirectUrl);
$oidc->addScope($scope);
$oidc->addAuthParam(['ui_locales' => 'en']);

$oidc->authenticate();

$profile = $oidc->getVerifiedClaims('profile_attributes');

foreach($profile as $key=>$value) {
    if(is_array($value)){
            $v = implode(', ', $value);
    }else{
            $v = $value;
    }
    $session[$key] = $v;
}


session_start();
$_SESSION['attributes'] = $session;

header("Location: ./attributes.php");

?>
```
<br>
7. Create `.env` file with your OAuth client configuration parameters

```conf
ISSUER="https://test-auth.eeid.ee/hydra-public/"
OAUTH_CLIENT_ID="<your-eeid-client-id>"
OAUTH_CLIENT_SECRET="<your-eeid-secret>"
CLIENT_REDIRECT_URI="http://localhost:8082/index.php"
AUTHORIZATION_SERVER_AUTHORIZE_URL="https://test-auth.eeid.ee/hydra-public/oauth2/auth"
AUTHORIZATION_SERVER_ACCESS_TOKEN_URL="https://test-auth.eeid.ee/hydra-public/oauth2/token"
RESOURCE_OWNER_URL="https://test-auth.eeid.ee/hydra-public/userinfo"
RESOURCE_SERVER_URL="https://test-auth.eeid.ee/hydra-public/userinfo"
SCOPE="openid idcard mid smartid eidas"
```
<br>
Parameters like `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET` and `SCOPE` have been defined after
configuring the service in the [eeID manager](https://eeid.ee) (see [Getting Started](#getting-started)).
<br>
8. Add the `attributes.php` page. E.g:

```php
<?php
    session_start();
?>
<!DOCTYPE html>
<html lang="en">

<head>

   <meta charset="utf-8">
   <meta http-equiv="X-UA-Compatible" content="IE=edge">
   <meta name="viewport" content="width=device-width, initial-scale=1">
   <meta name="description" content="">
   <meta name="author" content="">

   <title>OpenID Connect: Released Attributes</title>

</head>

<body>

   <!-- Intro -->
   <div class="banner">
      <div class="container">

         <h3>
            Claims sent back from OpenID Connect
         </h3>
         <br/>
      </div>
   </div>

   <!-- Claims -->
   <div class="content-section-a" id="openAthensClaims">
      <div class="container">
         <div class="row">

               <table class="table" style="width:80%;" border = "1">
                 <?php foreach ($_SESSION['attributes'] as $key=>$value): ?>
                      <tr>
                          <td data-toggle="tooltip" title=<?php echo $key; ?>><?php echo $key; ?></td>
                          <td data-toggle="tooltip" title=<?php echo $value; ?>><?php echo $value; ?></td>
                      </tr>
                 <?php endforeach; ?>

               </table>
         </div>
      </div>
   </div>
</body>

</html>
```
<br>
9. Go to `http://localhost:8082/index.php` in a browser. You will be sent to an eeID sign-in page.
After signing in you will be sent back and then on the attributes page.

![Claims](images/claims.png)

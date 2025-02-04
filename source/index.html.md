---

title: Estonian Internet Foundation's eeID Documentation

toc_footers:
   - <a href='https://internet.ee'>Estonian Internet Foundation</a>
   - <a href='https://eeid.ee'>Sign Up for eeID</a>
   - <a href='https://github.com/slatedocs/slate'>Powered by Slate</a>
includes:

search: true
code_clipboard: true
---

# Introduction

![eeID](images/eeid_logo.png)

Welcome to the Estonian Internet Foundation's eeID documentation! This document describes the technical characteristics of the Estonian Internet Foundation eeID services and includes advice for interfacing the client application with e-services. The Estonian Internet Foundation's eeID services offer a robust and secure framework for identity management, enabling both authentication and identification processes for users and organizations.

## Key Components
### [eeID Authentication Service](#eeid-authentication):

- The authentication service is based on the OpenID Connect protocol, which is an extension of the OAuth 2.0 framework. It provides a standardized method for verifying user identities across various applications and platforms.
- Users can authenticate using multiple methods, including Mobiil-ID, ID card, Smart-ID, EU-citizen cross-border authentication and FIDO2 Web Authentication (Passkey Authentication). This flexibility allows institutions and private individuals to choose the most suitable authentication method for their needs.
- The service issues identity tokens that contain essential user information, enabling applications to confirm identities and manage user access securely.

### [eeID Identification Service](#eeid-identification):

- The identification service complements the authentication service by providing an API for creating identification requests and verifying user identities based on specific criteria, such as unique identifiers (subject) or personal details (name).
- Organizations can initiate identification requests to confirm user identities, ensuring accurate matches against the provided information. This service is particularly valuable in sectors that require stringent identity verification, such as finance, healthcare, government, and domain registries, especially in light of the recently applied [NIS2 directive](https://digital-strategy.ec.europa.eu/en/policies/nis2-directive), which emphasizes the importance of robust cybersecurity measures and identity verification processes.
- By streamlining the identification process, the service enhances security and efficiency, allowing organizations to manage user verification seamlessly.

# OpenID Connect

The eeID is based on the OpenID Connect protocol (OIDC), which is built on top of the OAuth 2.0 authorization framework. It's designed to provide a secure and standardized way to authenticate users and obtain their basic profile information. OIDC is commonly used in applications that require user authentication, such as web and mobile applications.

Limited subset from standards was chosen and some adjustments were made. The main selections and adjustments compared to the full OpenID Connect protocol are the following:

- The services support the authorization code flow. The authorization code flow is deemed the most secure option and is thus appropriate for public services.
- All information about an authenticated user is transferred to the application in an ID token.
- The eIDAS assurance level is also transferred to the application if it is known (in the `acr` statement).
- The authentication method is selected by the user in the authentication service or by the interfaced client with the scope parameter.
- Cross-border authentication based on the technical specification of eIDAS.
- Dynamic registration of the client application is not supported. The client application is registered in [eeID manager](https://eeid.ee) by a separate procedure.

# Getting Started

In order to get started you have to sign up and create your first service in the [eeID manager](https://eeid.ee). 

1. Add a new contact first. From the main menu select `Contacts` to go to the contacts management view. Click on + Create New Contact and fill in the form.
![Create New Contact](images/new_contact_form.png)

2. From the main menu select `Services` to go to the service management view. Click on + Create New Service.
![Create New Service](images/create_new_service.png)

3. Fill in the form
![New Service Form](images/new_service_form.png)

4. All the fields must be valid to proceed.

* **Name** - enter the name for your service. NB! This will ultimately appear in-front of your customers.
* **Type** - enter the type of your service (`Authentication` or `Identification`)
* **Description** - provide a brief description of your service. It should be concise, ideally one sentence.
* **Approval description** - in this field, provide details about what you are building and who your target customers are.
* **Redirection URL** (`Authentication`) - specify the URL where users should be redirected to after they have been authenticated. If you do not know what you will use, just enter `http://localhost/callback` for now. The value can be changed later if needed. NB! Ensure that redirect URL uses the HTTPS protocol. HTTP is only permitted for local development environments (e.g., localhost).
* **Webhook URL** (`Identification`) - specify the URL where the service will send notifications about the status of identification requests. This is a critical field for services that require real-time updates on the verification process. Ensure the provided URL is secure (HTTPS) and can handle incoming requests. The path must contain `eeid/webhooks/identification_requests`.
* **Environment** - indicate the environment in which you will be using the service. `Test` is free and used for testing purposes.
* **Authentication scope** - choose the authentication scope you wish to support. The following scopes are supported: `openid`, `webauthn`, `phone` and `email`. NB! `idcard`, `mid`, `smartid` and `eidas` are no longer in use and will be removed.
* **Authentication methods** - choose the authentication methods you wish to support. You can select one or more methods based on your preferred country.
* **Contact** - choose an existing contact or create a new one. This contact will be associated with the service, and it might be the point of contact for any communications or notifications regarding the service.
* **Consent screen** (`Authentication`) - configure it to skip the "consent screen", which is the screen where the user must explicitly agree to giving the service access to their data and allow perform operations on their behalf.
* **Choose logo** (`Authentication`) - upload a logo for your service.
* **Submission** - review all the details entered in the form, and if everything is correct, click on `SUBMIT FOR APPROVAL` to submit your service.

Once you submit the form, it will be reviewed by the service administrators
at the [Estonian Internet Foundation](https://www.internet.ee/)
They will assess the details provided in your application to ensure
they meet the necessary criteria and adhere to the [terms of use](https://meedia.internet.ee/files/Terms_of_use_eeID.pdf).
If your application meets all the requirements, it will be approved and you will be provided with the `Client ID` and `Secret`.
In case there are issues or discrepancies in your application, it might be rejected.
After the review process is completed, you will receive a notification regarding the
status of your application. This notification will inform you whether your application has
been approved or rejected.

# Authentication scope

By default, the eeID services facilitate the following authentication scope:

* `openid` - compulsory (required by the OpenID Connect protocol).

* `phone` - can be used to request the user’s phone number in the identity token. This option is targeted for client applications that use i.e Mobile-ID, which requires user’s phone number for input, as a means for giving digital signatures. The claims `phone` and `phone_number_verified` are issued in the identity token. For example:

```shell
"sub": "EE60001019906",
"phone_number": "+37200000766",
"phone_number_verified": true
```

* `email` - can be used to request the user’s e-mail address in the identity token. This option is targeted for the client applications that require verification of an e-mail address in authentication of a user. The claims `email` and `email_verified` are issued in the identity token. For example:

```shell
"sub": "EE60001019906",
"email": "60001019906@eesti.ee",
"email_verified": false
```

* `webauthn` - authentication scope leverages passkeys, a cutting-edge technology that replaces traditional passwords with a more secure and user-friendly approach. Passkeys, as described in [FIDO Alliance's Passkeys 101](https://fidoalliance.org/passkeys-101/), utilize public key cryptography to enable users to authenticate using local authenticators such as biometrics, security keys, or other trusted devices. This method simplifies the authentication process while significantly enhancing security, providing a seamless and secure experience for users across the web.

<b>Creating a WebAuthn Credential through eeID:</b>

1. <b>Initial Authentication</b>
<br>Before creating a WebAuthn credential (passkey), users must first verify their identity using an authentication method provided by the eeID service or, if unavailable, an AI-powered identity verification platform ([Veriff](https://www.veriff.com/)). This step is crucial for ensuring the user's identity is securely verified through a recognized and trusted authentication method.

2. <b>eeID as Identity Provider</b>
<br>Once the initial authentication is successful, the eeID service acts as an identity provider.
In this role, it verifies and stores the authenticated data, establishing a secure and
trusted identity framework for the user.

3. <b>Creating the Webauthn Credential (passkey)</b>
<br>Following the successful authentication through eeID,
the user can proceed to create a passkey. This process involves:
    * <b>Registering a Local Authenticator.</b> The user will register a local authenticator,
    such as a biometric identifier (fingerprint, facial recognition, etc.) or a security key.
    * <b>Public Key Cryptography.</b> The WebAuthn method leverages public key cryptography,
    where a private key is stored on the user's local device, and a public key is
    stored on the server. This setup ensures a secure and password-less authentication process.
    * <b>Credential ID.</b> Upon successful registration, a unique Credential ID is generated, which will be used for future authentications.

<br>
4. <b>Future Authentications</b>
<br>With the passkey created, the user can now use this method for future authentications. When logging in:

    * The user will be prompted to authenticate using their local authenticator.

    * The server verifies the authentication using the stored public key, ensuring a secure and swift login process.

Creating a passkey through the eeID service not only enhances the security of
online transactions but also offers a user-friendly authentication experience.
It represents a forward step in secure, password-less digital authentication,
promoting ease of use without compromising on security.

# eeID Authentication

## Requests 

### Authentication request

An authentication request is a HTTP GET request by which the user is redirected from the client application to the eeID server for authentication.

URL: `https://auth.eeid.ee/hydra-public/oauth2/auth`

Required query parameters:

- `client_id` - service identifier issued upon registration of the client application in eeID portal
- `state` - security code against false request attacks (cross-site request forgery CSRF)
- `redirect_uri` - redirect_uri
- `response_type` - determines the manner of communication of the authentication result to the server, must be equal to `code`
- `scope` - authentication scope. The scope must correspond to the authentication scope selected while registering the service.

Optional query parameters:

- `ui_locales` - selection of the user interface language. The following languages are supported: `et`, `en`, `ru`
- `nonce` - unique parameter which helps to prevent replay attacks based on the protocol

An example of an authentication request:

```shell
GET https://auth.eeid.ee/hydra-public/oauth2/auth?client_id=oidc-b8ab3705-c25f-4271-b87d-ecf190aa4982-11
&redirect_uri=https%3A%2F%2Feservice.institution.ee%2Fcallback
&response_type=code
&scope=openid%20webauthn
&state=f3b2c3e7f4cf0bed3a783ed6ece617e3
```

### Redirect request

The redirect request is a HTTP GET request which is used to redirect the user back to the return address entered upon registration of the client application in [eeID manager](https://eeid.ee). In the redirect request an authorization code is sent to the client application, based on which the client application will request the access token in order to get personal identification code, name and other attributes of the authenticated person. The security code state received in the authentication request is mirrored back. Read more about forming and verifying state from [Protection against false request attacks](#protection).

An example of a redirect request:

```shell
GET https://eservice.institution.ee/callback?code=71ed5797c3d957817d31&
state=OFfVLKu0kNbJ2EZk
```
<br>
Request might contain other URL parameters, that client application must ignore.

If eeID is unable to process an authentication request - there will be an error in the request. eeID transfers an error message (URL parameter `error`) and the description of the error (URL parameter `error_description`) in the redirect request:

```shell
GET https://eservice.institution.ee/callback?error=invalid_scope&error_description=
The+requested+scope+is+invalid%2C+unknown%2C+or+malformed.+The+OAuth+2.0+Client+is+not+allowed+to+request+scope+%27invalid_scope%27.
&state=0b60fe50138f8fdd56afd2a6ab7a40f9
```
<br>
The redirect request errors are normally resulted by a misconfiguration; therefore the error description in parameter `error_description` is not needed to be displayed for the user directly. The client application should check whether or not an error message has been sent.

### Identity token request

The identity token request is an HTTP POST request which is used by the client application to request the identity token from the login server of eeID.

An example of an identity token request:

```shell
POST https://auth.eeid.ee/hydra-public/oauth2/token
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
`redirect_uri`| The redirect URL sent in the authorisation request

The server verifies that the identity token is requested by the right application and issues the identity token included in the response body. The response body uses JSON format consisting four elements:

Element        | Description
-------------- | --------------
`access_token` | OAuth 2.0 access certificate. With access token the client application can issue authenticated user’s data from `userinfo` endpoint.
`token_type` | OAuth 2.0 access token type with bearer value
`expires_in`| The validity period of the OAuth 2.0 access token
`id_token` | Identity token. Presented in [JWS Compact Serialization](https://tools.ietf.org/html/rfc7515#section-3.1) form

The identity token is a certificate of the fact of authentication issued by eeID. The identity token is issued in [JSON Web Token](https://jwt.io/), JWT format. The identity token is always [signed](https://tools.ietf.org/html/rfc7515#section-5.2). Example:

```json
{
  "jti": "0c597356-3771-4315-a129-c7bc1f02a1b2",
  "iss": "https://auth.eeid.ee",
  "aud": "oidc-b8ab3705-c25f-4271-b87d-ecf190aa4982-12",
  "exp": 1530295852,
  "iat": 1530267052,
  "nbf": 1530266752,
  "sub": "EE60001019906",
  "profile_attributes": {
    "date_of_birth": "2000-01-01",
    "family_name": "O’CONNEŽ-ŠUSLIK TESTNUMBER",
    "given_name": "MARY ÄNN"
  },
  "amr": [
    "mID"
  ],
  "state": "1OnH3qwltWy81fKqcmjYTqnco9yVQ2gGZXws/DBLNvQ=",
  "nonce": "",
  "at_hash": "X0MVjwrmMQs/IBzfU2osvw=="
}
```
<br>
The following claims are presented in the identity token:

| JSON element (claim)             | Description
| --------------------------- | ----------------
| `jti` | Identity token identifier
| `iss` | Issuer of the certificate
| `aud` | ID of a client application that requested authentication (the value of `client_id` field specified upon directing the user to the authentication process)
| `exp` | `1530295852` - expiration time of the certificate (in Unix epoch format)
| `iat` | `1530295852` - time of issue of the certificate (in Unix epoch format)
| `nbf` | `1530295852` - validity start time of the certificate (in Unix epoch format)
| `sub` | The identifier of the authenticated user (personal identification code or eIDAS identifier) with the prefix of the country code of the citizen (country codes based on [the ISO 3166-1 alpha-2 standard](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2#:~:text=ISO%203166%2D1%20alpha%2D2%20codes%20are%20two%2Dletter,special%20areas%20of%20geographical%20interest.)).
| `profile_attributes` | The data of the authenticated user, including the eIDAS attributes
| `profile_attributes.date_of_birth` | `2000-01-01` - the date of birth of the authenticated user in the ISO_8601 format.
| `profile_attributes.given_name` | The first name of the authenticated user
| `profile_attributes.family_name` | The surname of the authenticated user
| `amr` | The authentication method used for user authentication. Example values: `mID` - Mobile-ID, `idcard` - Estonian ID card, `eIDAS` - cross-border, `smartid` - Smart-ID
| `acr` | `high` - level of authentication based on the eIDAS LoA (level of assurance). Possible values: `low`, `substantial`, `high`
| `state` | The authentication request's `state` parameter value
| `nonce` | The authentication request's `nonce` parameter value. Value is present only in case the `nonce` parameter was sent in the authentication request
| `at_hash` | The access token hash (not used)
| `email` | The user's e-mail address (if present)
| `email_verified` | `false` - the e-mail address of the user has not been verified
| `phone_number` | `+37200000766` - the phone number is presented in E.164 format and prefixed by a country code (if present)
| `phone_number_verified` | `true` - the ownership of the phone number to the authenticating user has been confirmed

Identity token might consist of other OpenID Connect protocol based fields that are not supported by eeID.

The client application must obtain the identity token immediately or within `30` seconds (before the expiry time of the identity token).

### User info request

User info request enables requesting information about an authenticated user based on a valid `OAuth 2.0` access token. The request must be done by using the HTTP GET method. The access token must be presented to the user info endpoint in the HTTP header by using [the Bearer Token method](https://tools.ietf.org/html/rfc6750#section-2.1) or as a [URLi parameter](https://tools.ietf.org/html/rfc6750#section-2.3).

Example 1 - transferring an access certificate in the `Authorization` header:

```shell
GET https://auth.eeid.ee/hydra-public/userinfo
Auhtorization: Bearer AT-20-qWuioSEtFhYVdW89JJ4yWvtI5SaNWep0
```
<br>
Example 2 – transferring of access certificate as an `access_token` parameter:

```shell
GET https://auth.eeid.ee/hydra-public/userinfo?access_token=AT-20-qWuioSEtFhYVdW89JJ4yWvtI5SaNWep0
```
<br>
The valid access token response is provided in the JSON format. Example:

```json
{
  "acr": "high",
  "auth_time": 1694591147,
  "authentication_type": "SMART_ID",
  "date_of_birth": "2000-01-01",
  "family_name": "O’CONNEŽ-ŠUSLIK TESTNUMBER",
  "given_name": "MARY ÄNN",
  "sub": "EE60001019906",
}
```
<br>
The claims included in the response are issued based on the identity token.

| JSON element (claim)        | Description
| --------------------------- | ----------------
| `auth_time` | The time of successful authentication of the user
| `sub` | The identifier of the authenticated user (personal identification code or eIDAS identifier) with the prefix of the country code of the citizen (country codes based on [the ISO 3166-1 alpha-2 standard](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2#:~:text=ISO%203166%2D1%20alpha%2D2%20codes%20are%20two%2Dletter,special%20areas%20of%20geographical%20interest.))
| `authentication_type` | The authentication method used for user authentication. Example values: `MOBILE_ID` - Mobile-ID, `ID_CARD` - Estonian ID card, `SMART_ID` - Smart-ID, `WEBAUTHN` - Fido Webauthn
| `acr` | `high` - level of authentication based on the eIDAS LoA (level of assurance). Possible values: `low`, `substantial`, `high`
| `date_of_birth` | The date of birth of the authenticated user in the ISO_8601 format
| `given_name` | The first name of the authenticated user
| `family_name` | The surname of the authenticated user

Response body might contain other fields, that client application may ignore.

In case the access token presented to the user information endpoint is missing or is expired, an error code and a brief description 
about the error are returned:

```json
{
  "error": "invalid_token",
  "error_description": "Token expired. Access token expired at '2022-10-07 14:55:34 +0000 UTC'."
}
```

## Protection

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

## Endpoints and timeouts

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

## Testing

A prerequisite for testing the eeID authentication service is registering a service in test environment. After approving your service, it is possible to test the service immediately, using the credentials generated after approving.

Users for successful authentication:

- Mobile ID phone and id numbers: EE - `00000766` | `60001019906`, LT - `60000666` | `50001018865`
- Smart-ID personal codes: EE - `30303039914`, LV - `030303-10012`, LT - `30303039914`, BE - `06090199964`
- eIDAS country Czech Republic: select `Testovací profily` from the redirection screen and select a test user for authentication

### Mobile ID

The eeID test environment is directed to the Mobiil-ID demo environment. Public test numbers are available for use:

* Test numbers are available [here](https://github.com/SK-EID/MID/wiki/Test-number-for-automated-testing-in-DEMO). Apply only Estonian (EE) test numbers and personal identification codes.

### Smart ID

The eeID test environment is directed to the Smart-ID demo environment. There are two options for use:

* Install the Smart-ID demo application on your device and register a [demo account](https://github.com/SK-EID/smart-id-documentation/wiki/Smart-ID-demo#getting-started).
* Use [test users](https://github.com/SK-EID/smart-id-documentation/wiki/Environment-technical-parameters#test-accounts-for-automated-testing).

## Run in Postman
[<img src="https://run.pstmn.io/button.svg" alt="Run In Postman" style="width: 128px; height: 32px;">](https://god.gw.postman.com/run-collection/37760758-c07af2ef-c1d1-4675-91d1-701c0ea51871?action=collection%2Ffork&source=rip_markdown&collection-url=entityId%3D37760758-c07af2ef-c1d1-4675-91d1-701c0ea51871%26entityType%3Dcollection%26workspaceId%3Dfbfde0f7-54e9-4061-844a-5f03ab3d2ac4)

## Code examples

### OpenID Connect Client with Spring Security

One of the key features of Spring Security 5 was the native support for OAuth2 and OIDC.
Making use of the OIDC configuration information (OIDC metadata), integrating with
the eeID Server gets super easy. This tutorial shows how to use a registered service to login via eeID and access the user details within an ID-token.

<b>Prerequisites</b>

You should be familiar with Java, Spring Boot, and Spring Security.
Optionally, you should know how to use IntelliJ IDEA, but you can use any IDE of your choice.
Make sure you [configure an authentication service](#getting-started) in the [eeID manager](https://eeid.ee) before getting started.

<b>Setting up the project</b>

1. Visit [start.spring.io](https://start.spring.io/) to create a new Spring Boot project
2. Select Maven as your build tool and Java as your language
3. Change the group to something meaningful and name your project
4. Choose JDK 17 (or the latest available)
5. Search for and add the following dependencies: Spring Security, OAuth2 Client, Spring Reactive Web, Thymeleaf

![Spring Initializr](images/spring_initializr.png)
6. Generate the application. Spring Initializr creates an archive with a bootstrap application that includes the selected dependencies. Download and extract the archive, and import the project in an IDE of your choice

<b>Add a Starting Site</b>

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

<b>Add a Controller</b>

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

<b>Protect the User Area</b>

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

<b>Configure the OAuth Client</b>

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
            scope: openid
        provider:
          eeid:
            issuer-uri: https://test-auth.eeid.ee/hydra-public
```
<br>
This triggers Spring Boot to register a client. The client registration gets the id `eeid` which is part of the (default) `redirect-uri`.
The remaining properties, `client-id`, `client-secret` and `scope` have been defined when
configuring the client in the [eeID manager](https://eeid.ee) (see [Getting Started](#getting-started)). Make sure you configured correct callback url which is in our case must be `http://localhost:8080/login/oauth2/callback/eeid`.
You can choose any descriptive `client-name`. This is the string that is used in the default
login page setup at `/login`.
<br>
Spring Boot Security loads all the necessary OpenID configuration from the metadata
at [https://test-auth.eeid.ee/hydra-public/.well-known/openid-configuration](https://test-auth.eeid.ee/hydra-public/.well-known/openid-configuration)
and ensures that the user-agent gets redirected to the right endpoints for authentication.

<b>Run the Demo Application</b>

Start the demo application with `mvn spring-boot:run`. Navigate to `http://localhost:8080` to access the index site.
Click on the link to access `http://localhost:8080/secured` that triggers a login.

![Login Screen](images/login_screen.png)
<br>
After successful login the page shows details retrieved from the ID token.

![Login Details](images/login_details.png)
<br>
You can also navigate to `http://localhost:8080/login` to directly access the default login page created by Spring Security.

For further examples and help regarding OAuth2 and Spring Security for a reactive web application visit [Spring Security Reference Documentation](https://docs.spring.io/spring-security/reference/reactive/oauth2/login/index.html).

### PHP OpenID Connect example

Make sure you [configure am authentication service](#getting-started) in the [eeID manager](https://eeid.ee) before getting started.
<br>
This example uses the jumbojett basic OpenID Connect client and phpdotenv installed using composer and running on Docker container.

* jumbojett: [https://github.com/jumbojett/OpenID-Connect-PHP](https://github.com/jumbojett/OpenID-Connect-PHP)
* phpdotenv: [https://github.com/vlucas/phpdotenv](https://github.com/vlucas/phpdotenv)
* composer: [https://getcomposer.org/](https://getcomposer.org/)

It takes users to an attributes page after login and display the claims/values that have been passed.
In the real world you would read the claims and feed them into your authorisation/user-session management process.

<b>Instructions</b>

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
ISSUER="https://test-auth.eeid.ee/hydra-public"
OAUTH_CLIENT_ID="<your-eeid-client-id>"
OAUTH_CLIENT_SECRET="<your-eeid-secret>"
CLIENT_REDIRECT_URI="http://localhost:8082/index.php"
AUTHORIZATION_SERVER_AUTHORIZE_URL="https://test-auth.eeid.ee/hydra-public/oauth2/auth"
AUTHORIZATION_SERVER_ACCESS_TOKEN_URL="https://test-auth.eeid.ee/hydra-public/oauth2/token"
SCOPE="openid"
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

### Rails on Rails with OmniAuth::OpenIDConnect

In this example, we will make use of [OmniAuth::OpenIDConnect](https://github.com/omniauth/omniauth_openid_connect) gem, which contains the OpenID Connect (OIDC) strategy for OmniAuth library that standardizes multi-provider authentication for web applications.

<b>Getting Started</b>

Start by generating your Rails application with Bootstrap using ESBuild to build both the JavaScript and CSS files. From the terminal, run the command to do so:

```shell
rails new eeid_demo -T -j esbuild --css bootstrap
```
<br>
Create a partial named `_navigation.html.erb` to hold your navigation code. The partial should be located in the `app/views/layouts` directory. Enter the code below into an IDE. It uses Bootstrap to create a navigation bar for your application.

```erb
<nav class="navbar navbar-expand-lg bg-body-tertiary">
  <div class="container-fluid">
    <a class="navbar-brand" href="#">eeID Demo</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav">
        <li class="nav-item">
          <%= link_to 'Home', root_path, class: 'nav-link active' %>
        </li>
      </ul>
    </div>
  </div>
</nav>
```
<br>
For the navigation to be used, we need to render it in the application layout. Change application layout to look like this:

```erb
<!DOCTYPE html>
<html>
  <head>
    <title>eeID Demo</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <%= csrf_meta_tags %>
    <%= csp_meta_tag %>

    <%= stylesheet_link_tag "application", "data-turbo-track": "reload" %>
    <%= javascript_include_tag "application", "data-turbo-track": "reload", defer: true %>
  </head>

  <body>
    <%= render "layouts/navigation" %>
    <% flash.each do |key, value| %>
      <div class="<%= flash_class(key) %>">
        <%= value %>
      </div>
    <% end %>
    <div class="container-fluid">
      <%= yield %>
    </div>
  </body>
</html>
```
<br>
In order to display flash messages with the Bootstrap alert styles, extend `application_helper.rb` with the following method:

```ruby
def flash_class(level)
  flash_classes = {
    notice: 'alert alert-info',
    success: 'alert alert-success',
    error: 'alert alert-error',
    alert: 'alert alert-error'
  }

  flash_classes[level.to_sym]
end
```
<br>
Generate a `PagesController` with an index action by entering the command below into your terminal.

```shell
rails generate controller Pages index
```
<br>
In the index view generated, edit it to look like this:

```erb
<div class="jumbotron">
  <h1>Welcome to eeID Demo!</h1>
</div>
```
<br>
Open routes file to add our `root_path`:

```shell
# config/routes.rb

Rails.application.routes.draw do
  root to: 'pages#index'
end
```
<br>
<b>Setting Up OmniAuth Openid Connect</b>

We need to create a new eeID authenitcation service application. Go to [eeID manager](https://eeid.ee) to create one. Enter all the necessary details:

![Demo Service](images/demo_service.png)

For the callback URL, enter your website's address plus `auth/eeid/callback`. If you happen to be on a local machine, your callback URL should be this: `http://127.0.0.1:3000/auth/eeid/callback`

After submitting you will be redirected to the service information page. Copy the `Client ID` and `Client Secret` and paste them in a safe place — we will make use of them shortly.
The callback URL is the URL where a user will be redirected to inside the app after successful authentication and approved authorization (the request will also contain the user’s token). All OmniAuth strategies expect the callback URL to equal `/auth/:provider/callback`. `:provider` takes the name of the strategy. In our case, the strategy will be `eeid` as you will list in the initializer.

Open up Gemfile to add the necessary gems:

```ruby
# Gemfile
...
gem 'omniauth', '>=2.0.0'
gem 'omniauth_openid_connect'
gem 'omniauth-rails_csrf_protection'
```
<br>
Now create an initializer for OmniAuth in your config/initializers directory. This will hold the configuration for OmniAuth:

```ruby
# config/initializers/omniauth.rb

# Block GET requests to avoid exposing self to CVE-2015-9284
OmniAuth.config.allowed_request_methods = [:post]

Rails.application.config.middleware.use OmniAuth::Builder do
  provider :openid_connect, {
    name: :eeid,
    scope: ENV['SCOPES'].split(','),
    state: SecureRandom.hex(10),
    client_signing_alg: :RS256,
    send_scope_to_token_endpoint: false,
    send_nonce: true,
    issuer: ENV['ISSUER'],
    discovery: true,

    client_options: {
      identifier: ENV['IDENTIFIER'],
      secret: ENV['SECRET'],
      redirect_uri: ENV['REDIRECT_URL'],
    },
  }
end
```
<br>
We need to keep all the necesary private data safe as we do not want to push them to a public repository when we commit our code. We will make use of a [special gem](https://github.com/bkeepers/dotenv) for this. Open Gemfile again and add the gem below. Add it to Gemfile like so:

```ruby
# Gemfile
...
group :development, :test do
  ...
  gem 'dotenv-rails'
...
```
<br>
To install the gems, run:

```shell
bundle install
```
<br>
In the home directory create a file called `.env`.

```ruby
# .env

ISSUER="https://test-auth.eeid.ee/hydra-public"
IDENTIFIER="<your-eeid-client-id>"
SECRET="<your-eeid-secret>"
REDIRECT_URL="http://localhost:3000/auth/eeid/callback"
SCOPES="openid"
```
<br>
Open `.gitignore` and add the file we just created.

```ruby
# .gitignore
...
# Ignore .env used for storing id and secret
.env
```
<br>
Time to work on our routes. Open up the routes file and add the route below:

```ruby
# config/routes.rb

Rails.application.routes.draw do
  ...
  get '/auth/:provider/callback', to: 'sessions#create'
  ...
end
```
<br>
We need to add the link for eeID sign-in to navigation and to show this link only when the user is not signed in. Open navigation file and change it to look like this:

```erb
<nav class="navbar navbar-expand-lg bg-body-tertiary">
  <div class="container-fluid">
    <a class="navbar-brand" href="#">eeID Demo</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav">
        <li class="nav-item">
          <%= link_to 'Home', root_path, class: 'nav-link active' %>
        </li>
        <% if current_user %>
          <li class="nav-item nav-link">Signed in as <%= current_user.first_name %></li>
        <% else %>
          <li class="nav-item"><%= button_to 'Sign in with eeID', '/auth/eeid', class: 'nav-link', data: { turbo: false } %></li>
        <% end %>
      </ul>
    </div>
  </div>
</nav>
```
<br>
<b>Creating Sessions</b>

We'll need a session controller to handle the logging in of users. Create a file for that in controllers directory. The `create` action helps create a session for users so they can be logged into your application. Without this, users have no means of logging in.

```ruby
# app/controllers/sessions_controller.rb

class SessionsController < ApplicationController
  def create
    @user = User.find_or_create_from_auth_hash(auth_hash)
    session[:user_id] = @user.id
    flash[:success] = 'Sucessfully logged in!'
    redirect_to root_path
  end

  protected

  def auth_hash
    request.env['omniauth.auth']
  end
end
```
<br>
We'll need a `current_user` method at this point. This will help us check if a user is logged in or out.
Open `app/controllers/application_controller.rb` and add the following:

```ruby
# app/controllers/application_controller.rb

class ApplicationController < ActionController::Base
  ...
  def current_user
    @current_user ||= User.find(session[:user_id]) if session[:user_id]
  end

  helper_method :current_user
  ...
end
```
<br>
<b>User Model</b>

Now generate a model for Users. Run this command to do so:

```shell
rails generate model User provider:string uid:string first_name:string last_name:string token:string
```
<br>
That should generate a migration file that looks like this:

```ruby
class CreateUsers < ActiveRecord::Migration[7.0]
  def change
    create_table :users do |t|
      t.string :provider
      t.string :uid
      t.string :first_name
      t.string :last_name
      t.string :token

      t.timestamps
    end
  end
end
```
<br>
Now migrate database by running:

```shell
rake db:migrate
```
<br>
Open up User model and make it look like this:

```ruby
# app/models/user.rb

class User < ApplicationRecord
  def self.find_or_create_from_auth_hash(auth_hash)
    user = where(provider: auth_hash.provider, uid: auth_hash.uid).first_or_create
    user.update(
      first_name: auth_hash.info.first_name,
      last_name: auth_hash.info.last_name,
      token: auth_hash.credentials.token,
    )
    user
  end
end
```
<br>
The code above stores some information belonging to the user. This includes the `first_name`, `last_name` and `token` of the user.

<b>Deleting Sessions</b>

In our application, we want to provide users the ability to log out. We will need a `destroy` action in `SessionsController` for this to work. Then a link will be added to navigation.

Add the `destroy` action to `SessionsController`:

```ruby
# app/controllers/sessions_controller.rb

class SessionsController < ApplicationController  
  ...
  def destroy
    if current_user
      session.delete(:user_id)
      flash[:success] = "Sucessfully logged out!"
    end
    redirect_to root_path
  end
  ...
end
```
<br>
Then add this link for logging out to navigation, so our navigation looks like this:

```erb
<nav class="navbar navbar-expand-lg bg-body-tertiary">
  <div class="container-fluid">
    <a class="navbar-brand" href="#">eeID Demo</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav">
        <li class="nav-item">
          <%= link_to 'Home', root_path, class: 'nav-link active' %>
        </li>
        <% if current_user %>
          <li class="nav-item nav-link">Signed in as <%= current_user.first_name %></li>
          <li class="nav-item"><%= button_to 'Log Out', logout_path, method: :delete, class: 'nav-link', data: { turbo: false } %></li>
        <% else %>
          <li class="nav-item"><%= button_to 'Sign in with eeID', '/auth/eeid', class: 'nav-link', data: { turbo: false } %></li>
        <% end %>
      </ul>
    </div>
  </div>
</nav>
```
<br>
Open up `config/routes.rb` to update our routes with the action we just created.

```ruby
Rails.application.routes.draw do
  ...
  delete '/logout', to: 'sessions#destroy'
  ...
end
```
<br>
Start up rails server and point browser to [http://localhost:3000](http://localhost:3000).

```shell
bin/dev
```

# eeID Identification

The eeID Identification Service allows organizations to create identification requests and verify user identities based on specific criteria. It is built on a robust framework that ensures security, compliance, and ease of use.

## Key Features

- **Secure Identity Verification**: The service provides a secure method for verifying user identities, ensuring that organizations can trust the information they receive.
- **Multiple Delivery Methods**: Clients can choose how they receive proof of identity documents, including email (default), API pull, or webhook delivery.
- **User-Friendly Interface**: The [eeID manager](https://eeid.ee) offers a no-code solution for clients to create identification requests easily.
- **Real-Time Notifications**: Clients can receive updates on the status of identification requests through webhooks.

## Getting Started

To begin using the eeID Identification Service, follow these steps:

1. **Sign Up**: Create an account on the [eeID Manager](https://eeid.ee).
2. **Create a Service**:
   - Navigate to the `Services` section in the eeID Manager.
   - Click on + Create New Service, select `Identification` type and fill in the required details:
   ![New Identification Service](images/new_identification_service_form.png)
3. **Submit the service for approval**

## Example Workflow

1. **View Identification Requests**:
   - Go to the identification service show page. Click the button **"View Identification Requests"** to see existing requests if any. 
2. **Create a New Request**:
   - Click the button **"Create New Request"**. A form will appear prompting you to enter the necessary claims:
  ![New Identification Request](images/new_identification_form.png)
3. **Enter Claims to Match**:
   - At least one of the following claims must be presented:
     - **sub**: This field represents the unique identifier or subject for the end-user.
     - **name**: This field allows you to specify the end-user's full name.
     - **birthdate**: This field captures the end-user's date of birth represented in YYYY-MM-DD format.
     - **country**: This field specifies the end-user's country in ISO 3166-1 Alpha-2 format.
   - Additionally, enter a **reference**:
     This reference serves as an identifier in the system of the calling service and will be included in the result if present.
4. **Submit the Request**:
   - Once all required data is entered, submit the form to create a new identification request.
   - The system generates a new identification request and provides a unique link for the end-user:
   ![Identification Request](images/identification_request.png)
5. **Send the Link to the End-User**:
   - It is your responsibility to send the generated link to the end-user for verification.
   - You can add a `ui_locales` parameter to the link in order to change the UI language. The supported languages are `ru` (Russian), `et` (Estonian), and `en` (English). For example, to change the UI language to Russian, add `?ui_locales=ru` to the end of the link.
6. **Verification Process**:
   - The end-user follows the link to complete the verification process with eeID.
   - The identification request is marked as **completed** once the end-user successfully finishes the verification process. An email will be sent to the identification service contact email. If a secure webhook URL was provided, the service will send a POST request with the proof of identity document once it is ready.
7. **Handling Aborted Requests**:
   - If the end-user aborts the flow without completing the assignment, the status of the identification request remains unchanged.
   - The end-user can follow the link again to complete the assignment at a later time. The generated link will be valid for **7 days**. If the verification process is not completed within this time frame, the identification request will expire.

## Identification Requests API

In addition to the no-code solution provided by the [eeID manager](https://eeid.ee), the eeID Identification Service offers a robust API for handling identification requests. This API allows developers to programmatically create, manage, and retrieve identification requests, providing greater flexibility and integration capabilities for applications.

### API Features

- **Create Identification Requests**: Easily submit new identification requests by providing the necessary claims, including the subject identifier (`sub`), full name (`name`), `country` or `birthdate`. This allows for automated request creation directly from your application.
- **Retrieve Identification Requests**: Access existing identification requests to check their status or retrieve detailed information. This feature enables applications to monitor the progress of requests and respond accordingly.
- **Proof of Identity Request**: Retrieve the proof of identity document in PDF format for a specific identification request. This feature is essential for applications that require access to verified identity documents for further processing or record-keeping.
- **Authorization**: The requests must be authenticated using a valid access token. Ensure that the token is included in the request header as follows:
```
Authorization: Bearer {access_token}
```

### API Documentation

Comprehensive API documentation is available for the eeID Identification Service. You can access it here: [eeID Identification Service API Documentation](https://internetee.github.io/eeID-ident-api-doc/).

For additional testing, the API is also available in Postman. You can explore the available endpoints, request parameters, and response formats directly in the Postman collection:

[<img src="https://run.pstmn.io/button.svg" alt="Run In Postman" style="width: 128px; height: 32px;">](https://god.gw.postman.com/run-collection/37760758-d649a287-c53e-483c-84d5-3b584a88b706?action=collection%2Ffork&source=rip_markdown&collection-url=entityId%3D37760758-d649a287-c53e-483c-84d5-3b584a88b706%26entityType%3Dcollection%26workspaceId%3D38bd2f07-e8f0-4bd4-ae32-1917d18f19a8)

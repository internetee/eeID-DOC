<img src="https://eeid.ee/images/eis-logo-white.svg" />

# eeID authentication

- [Overview](#overview)
- [Requests](#requests)
    * [Authentication request](#authentication_request)
    * [Redirect request](#redirect_request)
    * [Access token request](#access_token_request)
    * [User info request](#userinfo_request)
- [Protection against false request attacks](#protection)
- [Endpoints and timeouts](#endpoints)

<a name="overview"></a>
## Overview

This document describes the technical characteristics of the Estonian Internet Foundation eeID authentication service and 
includes advice for interfacing the client application with e-services. The eeID authentication service can be used by 
institutions and private persons to add the support of various different authentication methods to its e-service:
* Mobiil-ID
* ID card
* Smart-ID
* cross-border authentication (via eIDAS-Node)

In case of questions and to get help, please contact us: info@internet.ee.

<a name="requests"></a>
## Requests

<a name="authentication_request"></a>
### 1. Authentication request

An authentication request is a HTTP GET request by which the user is redirected from the client application to the eeID server for authentication. 

URL: ````https://eeid.ee/oidc/authorize````

Required query parameters:

`client_id` - service identifier issued upon registration of the client application in eeID portal

`state` - security code against false request attacks (cross-site request forgery CSRF)

Optional query parameters:

`lang` - selection of the user interface language (optional). The following languages are supported: et, en, ru.

An example of an authentication request:

````
HTTP GET https://eeid.ee/oidc/authorize?client_id=oidc-d1bcff5f-ba96-494a-a057-c9d9696bd5d0-980190969
&state=5394a7ea64bc8fa6fec47e9bf21cd93c&lang=et
````

<a name="redirect_request"></a>
### 2. Redirect request

The redirect request is a HTTP GET request which is used to redirect the user back from eeID to the return address 
entered upon registration of the client application in eeID. In the redirect request an authorization code is sent 
to the client application, based on which the client application will request the access token in order to get 
personal identification code, name and other attributes of the authenticated person. The security code `state` 
received in the authentication request is mirrored back. Read more about forming and verifying state from 
‘Protection against false request attacks’.

An example of a redirect request:

````
HTTP GET https://eservice.institution.ee/callback?code=71ed5797c3d957817d31&
state=OFfVLKu0kNbJ2EZk
````

Request might contain other URL parameters, that client application must ignore.

If eeID is unable to process an authentication request - there will be an error in the request. 
eeID transfers an error message (URL parameter `error`) and the description of the error 
(URL parameter `error_description`) in the redirect request:

````
HTTP GET https://eservice.institution.ee/callback?error=invalid_scope&error_description=
The+requested+scope+is+invalid%2C+unknown%2C+or+malformed.+The+OAuth+2.0+Client+is+not+allowed+to+request+scope+%27invalid_scope%27.
&state=0b60fe50138f8fdd56afd2a6ab7a40f9
````

The redirect request errors are normally resulted by a misconfiguration; therefore the error description in parameter `error_description` 
is not needed to be displayed for the user directly. The client application should check whether or not an error message has been sent.

<a name="access_token_request"></a>
### 3. Access token request

The access token request is an HTTP POST request which is used by the client application to request the access token.
An example of an access token request:

````
POST https://eeid.ee/oidc/token 
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content_Type: application/x-www-form-urlencoded
````
````
code=71ed5797c3d957817d31
````
The client secret code must be provided in the access token request. For this purpose, the request must include the `Authorization` request 
header with the value formed of the word `Basic`, a space and a string `<client_id>:<client_secret>` encoded in the Base64 format. The body 
of the HTTP POST request must be presented in a seriased [format](https://openid.net/specs/openid-connect-core-1_0.html#FormSerialization) 
based on the OpenID Connect protocol. The body of the request must include 
the `code` received from the authentication service. eeId server verifies that the access token is requested by the right application and 
issues the access token included in the response body. 

The response body uses JSON format consisting of four elements:

| Element        | Explanation |
| :---------------- | :----------------|
| `access_token` | OAuth 2.0 access certificate. With access token the client application can issue authenticated user’s data from `userinfo` endpoint. |
| `token_type` | OAuth 2.0 access token type with bearer value. |
| `expires_in` | The validity period of the OAuth 2.0 access token. |
| `state` | The authentication request’s state parameter value. |

The client application must obtain the access token immediately or within 30 seconds before the expiry time.

<a name="userinfo_request"></a>
### 4. User info request

User info request enables requesting information about an authenticated user based on a valid OAuth 2.0 access token. 
The request must be done by using the HTTP GET method.
The access token and  service identifier  must be presented to the user info endpoint in the HTTP header by using a URLi parameters.
Example  – transferring of access certificate as an `access_token` parameter:

````
HTTP GET https://eeid.ee/oidc/userinfo?access_token=AT-20-qWuioSEtFhYVdW89JJ4yWvtI5SaNWep0
&client_id=oidc-d1bcff5f-ba96-494a-a057-c9d9696bd5d0-980190969
````

The valid access token response is provided in the JSON format. Example:

````
{
   "date_of_birth": "2000-01-01",
   "family_name": "O’CONNEŽ-ŠUSLIK TESTNUMBER",
   "given_name": "MARY ÄNN",
   "id_code": "EE60001019906",
   "auth_time": "2022-10-07T22:01:48.000+03:00",
   "auth_method": "mID"
}
````
The claims included in the response are issued based on the identity token.

| JSON element (claim)        | Explanation |
| :---------------- | :----------------|
| `auth_time` | The time of successful authentication of the user. |
| `id_code` | The identifier of the authenticated user (personal identification code or eIDAS identifier) with the prefix of the country code of the citizen (country codes based on the ISO 3166-1 alpha-2 standard). |
| `date_of_birth` | The date of birth of the authenticated user in the ISO_8601 format. |
| `given_name` | The first name of the authenticated user. |
| `family_name` | The surname of the authenticated user. |
| `auth_method` | The authentication method used for user authentication. Possible values: `mID` - Mobile-ID, `idcard` - Estonian ID card, `smartid` - Smart-ID. |

In case the access token presented to the user information endpoint is missing or is expired, an error code and a brief description 
about the error are returned:

````
{
   "error": "invalid_token",
   "error_description": "Token expired. Access token expired at '2022-10-07 14:55:34 +0000 UTC'."
}
````

<a name="protection"></a>
## Protection against false request attacks

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

````
state=07f19702e7e9591c6fa2554e1fcf5f4a
````

Length of state parameter must be minimally 8 characters. In the course of processing the redirect request, the client application must:

4. Take the `ESERVICE` value of the cookie received with the request.

5. Verify that the `ESERVICE` value matches the state value mirrored back in the redirect request.

The redirect request may only be accepted if the checks described above are successful. 
The key element of the process described above is connection of the `state` value with the session. This is achieved by using a cookie.

<a name="endpoints"></a>
## Endpoints and timeouts

1. Production service

| Endpoint        | URL |
| :---------------- | :----------------|
| server discovery | https://auth.eeid.ee/hydra-public/.well-known/openid-configuration |
| authorization | https://eeid.ee/oidc/authorize |
| token | https://eeid.ee/oidc/token |
| userinfo | https://eeid.ee/oidc/userinfo |

2. Timeouts

| Timeout       | Value | Remark |
| :--------------------------------- | :--------------| :----------------|
| session | 30 min | eeID server creates a session with the user identified. If the user doesn’t perform any activity on eeID page, the session will expire in 30 minutes. Note: eeID session must be distinguished from the session between the client application and the user. |
| SSL/TLS handshake | 25 s | In case of ID-card authentication. The user must enter PIN1 within 25 seconds. After the timeout, the authentication will be terminated for security reasons. |
| OAuth authorization code | 30 s | The client application must obtain the access token using authorization code within 30 seconds. |


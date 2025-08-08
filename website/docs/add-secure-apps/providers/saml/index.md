---
title: SAML Provider
---

This provider allows you to integrate enterprise software using the SAML2 protocol. It supports signed requests and uses [property mappings](../property-mappings/index.md#saml-property-mappings) to determine which fields are exposed and what values they return. This makes it possible to expose vendor-specific fields.
Default fields are exposed through auto-generated Property Mappings, which are prefixed with "authentik default".

| Endpoint                  | URL                                                          |
| ------------------------- | ------------------------------------------------------------ |
| SSO (Redirect binding)    | `/application/saml/<application slug>/sso/binding/redirect/` |
| SSO (POST binding)        | `/application/saml/<application slug>/sso/binding/post/`     |
| SSO (IdP-initiated login) | `/application/saml/<application slug>/sso/binding/init/`     |
| SLO (Redirect binding)    | `/application/saml/<application slug>/slo/binding/redirect/` |
| SLO (POST binding)        | `/application/saml/<application slug>/slo/binding/post/`     |
| Metadata Download         | `/application/saml/<application slug>/metadata/`             |

You can download the metadata through the web interface. This link might be useful if your software needs to fetch the metadata directly.

The metadata download link can also be copied with a button on the provider overview page.

## Name ID

You can select a custom SAML Property Mapping to control how the NameID field is generated. When using the default configuration, authentik determines the NameID value based on the requested format:

| Value                                 | NameID Format                                                          | Fallback              |
| ------------------------------------- | ---------------------------------------------------------------------- | --------------------- |
| Hashed user ID                        | `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`                 | N/A                   |
| User's `distinguishedName` attribute¹ | `urn:oasis:names:tc:SAML:2.0:nameid-format:X509SubjectName`            | Persistent identifier |
| User Principal Name (UPN)¹            | `urn:oasis:names:tc:SAML:2.0:nameid-format:WindowsDomainQualifiedName` | Persistent identifier |
| User's session ID                     | `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`                  | N/A                   |
| User's email address                  | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`               | N/A                   |

¹ These attributes are typically set by LDAP sources.

:::warning
Keep in mind that with the default settings, users are free to change their email addresses. As such it is recommended to use `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`, as this cannot be changed.
:::

## SAML IDP Initiated Single Logout (SLO)

authentik supports SAML IDP Initiated Single Logout (SLO), which allows users to log out of authentik and all connected SAML service providers simultaneously.

### Logout Methods

When users log out of authentik, they are automatically logged out of all SAML service providers accessed during their session. authentik supports three logout methods:

- **Iframe-based front-channel logout** (default) - Performs parallel logout requests using hidden iframes
- **Redirect-based front-channel logout** - Sequential logout using browser redirects (legacy)
- **Back-channel logout** - Server-to-server POST requests without user interaction

:::info
Front-channel logouts occur in the user's browser, while back-channel logouts happen directly between servers and work even when sessions are terminated administratively.
:::

### Configuration

#### Single Logout Service URL

To enable SAML Single Logout, configure the **Single Logout Service (SLS) URL** in your SAML provider settings. This is the service provider's endpoint where authentik sends logout requests.

1. In your SAML provider, set the **SLS URL** field to your service provider's logout endpoint
2. Choose the appropriate **SLS Binding**:
    - **Redirect** - Uses HTTP redirects (front-channel only)
    - **POST** - Supports both front-channel and back-channel

:::tip
When using POST binding, you can enable **Backchannel Post Logout** for server-to-server logout. This ensures users are logged out even when their session is administratively terminated.
:::

#### Logout Stage Configuration

The front-channel logout behavior is controlled by the [User Logout stage](../../flows-stages/stages/user_logout.md) in your logout flow. By default, authentik uses iframes for efficient parallel logout. To switch to the legacy sequential redirect method:

1. Navigate to **Flows & Stages** → **Stages**
2. Edit your **User Logout** stage
3. Enable **Redirect based SAML Single Logout**

### Signing Logout Requests

For enhanced security, enable **Sign logout requests** in your SAML provider's settings. This signs all logout requests sent to service providers using the configured signing certificate.

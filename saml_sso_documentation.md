# SAML SSO Integration with Dify

## 1. SAML SSO Integration Overview

Dify supports SAML 2.0 based Single Sign-On (SSO), allowing users to authenticate using their existing corporate identities managed by a SAML 2.0 compatible Identity Provider (IdP) like Azure Active Directory, Okta, Auth0, etc.

When a user attempts to log in via SAML SSO for the first time, Dify can automatically create a user account for them through Just-In-Time (JIT) provisioning. This simplifies user management by eliminating the need for manual account creation within Dify.

## 2. Enabling SAML SSO

To enable SAML SSO in Dify, set the following environment variable:

*   `SAML_ENABLED=true`

If this variable is not set to `true`, the SAML SSO feature will be disabled, and other SAML-related configurations will be ignored.

## 3. Configuration Parameters

All SAML SSO settings are configured via environment variables. These variables are read by Dify at startup.

| Variable Name                     | Description                                                                                                                               | Example Value (Anonymized)                               | Default Value      |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ------------------ |
| `SAML_ENABLED`                    | Enables or disables the SAML SSO feature.                                                                                                 | `true`                                                   | `false`            |
| `SAML_PROVIDER_NAME`              | A unique name for this SAML provider configuration. Used internally by Authlib.                                                           | `AzureAD_SAML`                                           | `AzureAD_SAML`     |
| `SAML_DEBUG`                      | Enables detailed debugging logs from the Authlib SAML client. Useful for troubleshooting.                                                 | `true`                                                   | `false`            |
| `SAML_IDP_METADATA_URL`           | The URL to your Identity Provider's federation metadata XML file. This is often the preferred method as it simplifies IdP configuration.    | `https://login.microsoftonline.com/your-tenant-id/federationmetadata/2007-06/federationmetadata.xml` | `""`               |
| `SAML_IDP_ENTITY_ID`              | The Entity ID of your Identity Provider. Required if `SAML_IDP_METADATA_URL` is not provided or if metadata doesn't contain the Entity ID. | `https://sts.windows.net/your-tenant-id/`                | `""`               |
| `SAML_IDP_LOGIN_URL`              | The SSO login URL of your Identity Provider. Used if metadata URL is not available or to override the one in metadata.                     | `https://login.microsoftonline.com/your-tenant-id/saml2` | `""` (Not directly used if metadata URL is set) |
| `SAML_IDP_X509_CERT_PATH`         | Filesystem path to the Identity Provider's public X.509 certificate. Used to verify signatures from the IdP if metadata URL is not used. | `/etc/dify/certs/idp_cert.pem`                           | `""` (Not directly used if metadata URL is set) |
| `SAML_SP_ENTITY_ID`               | The Entity ID for Dify as a Service Provider (SP). This value must be configured in your IdP.                                            | `dify-sp` or `https://your-dify-domain.com/api/sso/saml/metadata` | `dify-sp`          |
| `SAML_ACS_URL_PATH`               | The path component for Dify's Assertion Consumer Service (ACS) URL. The full URL is derived (e.g., `https://<your-dify-domain>/api` + path). | `/sso/saml/acs`                                          | `/sso/saml/acs`    |
| `SAML_SLO_URL_PATH`               | The path component for Dify's Single Logout (SLO) URL. The full URL is derived.                                                           | `/sso/saml/slo`                                          | `/sso/saml/slo`    |
| `SAML_SP_X509_CERT_PATH`          | Filesystem path to Dify's public X.509 certificate. Used for signing requests or if encryption is enabled.                               | `/etc/dify/certs/saml_sp.crt`                            | `""`               |
| `SAML_SP_PRIVATE_KEY_PATH`        | Filesystem path to Dify's private key corresponding to `SAML_SP_X509_CERT_PATH`.                                                          | `/etc/dify/certs/saml_sp.key`                            | `""`               |
| `SAML_METADATA_CACHE_LIFETIME`    | Lifetime in seconds for caching the IdP metadata if `SAML_IDP_METADATA_URL` is used.                                                      | `3600` (1 hour)                                          | `3600`             |
| `SAML_SIGN_REQUEST`               | If `true`, Dify will sign SAML AuthnRequests sent to the IdP. Requires `SAML_SP_X509_CERT_PATH` and `SAML_SP_PRIVATE_KEY_PATH`.             | `false`                                                  | `false`            |
| `SAML_WANT_ASSERTIONS_SIGNED`     | If `true`, Dify will require SAML assertions received from the IdP to be signed.                                                          | `false`                                                  | `false`            |
| `SAML_WANT_RESPONSE_SIGNED`       | If `true`, Dify will require the entire SAML response (not just the assertion) from the IdP to be signed.                                 | `false`                                                  | `false`            |
| `SAML_ENCRYPT_ASSERTION`          | If `true`, Dify will expect SAML assertions to be encrypted. Requires Dify's SP certificate (`SAML_SP_X509_CERT_PATH`) to be uploaded to the IdP. | `false`                                                  | `false`            |
| `SAML_DEFAULT_USER_ROLE`          | The default role assigned to users provisioned via SAML SSO. Valid roles are typically 'admin', 'normal', 'viewer', etc.                 | `normal`                                                 | `normal`           |

**Note on Attribute Mapping:**
Currently, Dify expects standard SAML attributes for user provisioning. Common attributes include:
*   **Email:** `urn:oid:0.9.2342.19200300.100.1.3` or `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` or `email`.
*   **Given Name (First Name):** `urn:oid:2.5.4.42` or `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname` or `firstName`.
*   **Surname (Last Name):** `urn:oid:2.5.4.4` or `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname` or `lastName`.
*   **NameID:** A persistent, unique identifier for the user. This is usually the `NameID` element in the SAML assertion's Subject.

Ensure your IdP is configured to send these attributes in the SAML assertion.

## 4. Setting up SAML SSO with Azure Active Directory (Example)

This section provides a step-by-step guide to configure SAML SSO between Dify and Azure Active Directory.

### In Azure AD Portal:

1.  **Navigate to Enterprise applications:**
    *   Log in to the Azure portal (portal.azure.com).
    *   Go to **Azure Active Directory** -> **Enterprise applications**.
2.  **Create a New Application:**
    *   Click on **+ New application**.
    *   Click on **+ Create your own application**.
    *   Enter a name for your application (e.g., "Dify SAML SSO").
    *   Select **Integrate any other application you don't find in the gallery (Non-gallery)**.
    *   Click **Create**.
3.  **Set up Single Sign-On:**
    *   Once the application is created, go to its overview page.
    *   In the left navigation pane, click on **Single sign-on**.
    *   Select **SAML** as the single sign-on method.

### Basic SAML Configuration (in Azure AD):

On the "Set up Single Sign-On with SAML" page, click the **Edit** icon in the "Basic SAML Configuration" section.

*   **Identifier (Entity ID):**
    *   This is Dify's Service Provider Entity ID.
    *   It must exactly match the value you set for `SAML_SP_ENTITY_ID` in Dify's environment variables (e.g., `dify-sp` or `https://<your-dify-domain>/api/sso/saml/metadata`).
    *   Click **+ Add identifier** and enter the value.
*   **Reply URL (Assertion Consumer Service URL):**
    *   This is the URL where Azure AD will send the SAML assertion.
    *   It is composed of your Dify instance's base URL, `/api`, and the path from `SAML_ACS_URL_PATH`.
    *   Example: `https://<your-dify-domain>/api/sso/saml/acs` (replace `<your-dify-domain>` with your actual domain).
    *   Click **+ Add reply URL** and enter the value. Ensure it is marked as the primary Reply URL if multiple are present.
*   **Sign on URL (Optional):**
    *   This is the URL users can use to initiate an SP-initiated login.
    *   You can use Dify's main login page or the specific SAML login initiation URL.
    *   Example: `https://<your-dify-domain>/signin` or `https://<your-dify-domain>/api/enterprise/sso/saml/login`.
*   **Logout Url (Optional):**
    *   This is Dify's Single Logout URL.
    *   It is composed of your Dify instance's base URL, `/api`, and the path from `SAML_SLO_URL_PATH`.
    *   Example: `https://<your-dify-domain>/api/sso/saml/slo`.

Click **Save** after configuring these URLs.

### User Attributes & Claims (in Azure AD):

Dify requires certain attributes to be sent in the SAML assertion for user provisioning and identification.

1.  On the "Set up Single Sign-On with SAML" page, click the **Edit** icon in the "User Attributes & Claims" section.
2.  Ensure the following claims are present (Azure AD often includes some by default):
    *   **Unique User Identifier (Name ID):**
        *   This should be a persistent, unique identifier for the user.
        *   Common choices: `user.userprincipalname` (usually email-like), `user.objectid` (a globally unique ID).
        *   Ensure the "Name identifier format" is appropriate (e.g., `Persistent` or `EmailAddress` depending on the source attribute).
    *   **Email address:**
        *   Claim name: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` (standard claim type) or a simple name like `email`.
        *   Source attribute: `user.mail`.
    *   **Given Name (First Name):**
        *   Claim name: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname` or `firstName`.
        *   Source attribute: `user.givenname`.
    *   **Surname (Last Name):**
        *   Claim name: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname` or `lastName`.
        *   Source attribute: `user.surname`.
3.  You may need to **+ Add new claim** if these are not present or if you want to use different source attributes.
4.  Dify will use these attributes to create or update user profiles.

### SAML Signing Certificate (in Azure AD):

Azure AD uses a certificate to sign the SAML assertions it sends to Dify.

1.  On the "Set up Single Sign-On with SAML" page, find the "SAML Signing Certificate" section.
2.  **Federation Metadata XML URL:** Azure AD provides a **App Federation Metadata Url**. This URL should be used for Dify's `SAML_IDP_METADATA_URL` environment variable.
    *   Example: `https://login.microsoftonline.com/<your-tenant-id>/federationmetadata/2007-06/federationmetadata.xml?appid=<your-app-id>`
3.  Alternatively, you can download the "Federation Metadata XML" file and configure Dify by manually providing `SAML_IDP_ENTITY_ID`, `SAML_IDP_LOGIN_URL`, and `SAML_IDP_X509_CERT_PATH` (by extracting the certificate from the XML). Using the metadata URL is generally simpler.
4.  **Assertion Encryption:** If you have enabled `SAML_ENCRYPT_ASSERTION=true` in Dify:
    *   You must upload Dify's public SP certificate (the content of the file specified by `SAML_SP_X509_CERT_PATH`) to Azure AD.
    *   In Azure AD, this is typically done by editing the SAML application, going to "Token encryption", and uploading your certificate.

### Assign Users/Groups (in Azure AD):

By default, newly created enterprise applications in Azure AD do not allow any users to sign in.

1.  In the Azure AD portal, navigate to your Dify SAML application.
2.  Go to **Users and groups**.
3.  Click **+ Add user/group** and assign the users or groups who should be allowed to log in to Dify via SAML SSO.

## 5. Service Provider (Dify) Certificate and Private Key

These files (`SAML_SP_X509_CERT_PATH` and `SAML_SP_PRIVATE_KEY_PATH`) are required by Dify if:
*   `SAML_SIGN_REQUEST` is `true` (Dify needs to sign authentication requests sent to the IdP).
*   `SAML_ENCRYPT_ASSERTION` is `true` (Dify needs its private key to decrypt assertions encrypted by the IdP).
*   Some IdPs might require the SP's public certificate for validating signed logout requests or other purposes.

You can generate a self-signed certificate and private key pair using OpenSSL. For production environments, you might use certificates issued by a Certificate Authority (CA).

**Example using OpenSSL to generate a self-signed certificate (valid for 10 years):**

```bash
openssl req -x509 -newkey rsa:2048 -keyout saml_sp.key -out saml_sp.crt -days 3650 -nodes -subj "/CN=dify-sp"
```

*   `saml_sp.key`: This will be your private key. Set its path to `SAML_SP_PRIVATE_KEY_PATH`.
*   `saml_sp.crt`: This will be your public certificate. Set its path to `SAML_SP_X509_CERT_PATH`.
*   `-nodes`: Creates a key without a passphrase. If you use a passphrase, Dify must be able to access it.
*   `-subj "/CN=dify-sp"`: Sets the Common Name for the certificate. You can adjust this as needed.

Place these files in a secure location accessible by the Dify API server. Ensure the file paths configured in the environment variables are correct.

## 6. Dify Metadata URL

Dify exposes its Service Provider metadata at the following URL:

`https://<your-dify-domain>/api/sso/saml/metadata`

(Replace `<your-dify-domain>` with your actual Dify instance's domain).

Some Identity Providers allow you to configure the Service Provider (Dify) by providing this metadata URL, which can simplify the setup process on the IdP side as it often pre-fills the Entity ID, ACS URL, and SP certificate (if included in metadata).

## 7. Troubleshooting

If you encounter issues setting up SAML SSO, consider the following:

*   **Clock Skew:** SAML assertions are time-sensitive. Ensure that the server time on your Dify instance and the Identity Provider's servers are synchronized. Use NTP (Network Time Protocol) on your servers.
*   **Certificate Issues:**
    *   If `SAML_SIGN_REQUEST` or `SAML_ENCRYPT_ASSERTION` is enabled, ensure `SAML_SP_X509_CERT_PATH` and `SAML_SP_PRIVATE_KEY_PATH` point to valid, readable certificate and private key files.
    *   Ensure the correct IdP certificate is being used by Dify (either via metadata URL or `SAML_IDP_X509_CERT_PATH`).
    *   If you uploaded Dify's SP certificate to the IdP (for assertion encryption), ensure it's the correct one.
*   **Metadata Mismatch:**
    *   Double-check that the Entity IDs (`SAML_SP_ENTITY_ID` in Dify, Identifier in Azure AD) match *exactly*.
    *   Verify that the ACS URL (Reply URL) configured in the IdP matches Dify's expected ACS URL (`https://<your-dify-domain>/api` + `SAML_ACS_URL_PATH`).
*   **Enable Debugging:**
    *   Set `SAML_DEBUG=true` in Dify's environment variables.
    *   Check the Dify API server logs for detailed error messages. Authlib often provides specific information about what part of the SAML exchange failed.
*   **IdP Logs:** Check the sign-in logs or event logs in your Identity Provider (e.g., Azure AD's "Sign-in logs") for errors or details about failed login attempts.
*   **Browser Developer Tools:** Use your browser's developer tools (Network tab) to inspect the SAML requests and responses. Look for SAML AuthnRequests and SAMLResponses, and use online SAML decoders to inspect their content (be cautious with sensitive data).
*   **User Assignment:** Ensure the user attempting to log in is assigned to the SAML application in the IdP (e.g., in Azure AD "Users and groups").

By systematically checking these areas, you can often pinpoint the cause of SAML SSO integration problems.
```

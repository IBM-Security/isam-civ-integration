# ISAM + Cloud Identity integration
[Cloud Identity](http://www.ibm.com/security/identity-access-management/cloud-identity) is a new IBM offering that supports several multi-factor authentication types including IBM Verify. One advantage of leveraging authentication methods from the cloud is that the methods can be updated with newer technology more rapidly, and new methods can be adopted without the need for an IBM Security Access Manager update.

A second advantage is that Cloud Identity supplies both an email gateway and an SMS gateway, for SMS and Email OTP methods.

![Strong Auth](images/strong_auth.png)

The Cloud Identity authentication types can be leveraged from ISAM. Instead of redirecting users to Cloud Identity to perform authentication the new Cloud Identity API integration within ISAM 9.0.5.0 can be used. This allows for complete control over the look and feel of the authentication experience.

The API Integration is achieved through a series of Info Map rules as well as a new Authentication Mechanism type - Cloud Identity JavaScript. The new mechanism type is very similar to an Info Map mechanism, with a few extra properties.

### What is in this repo?

#### Mapping Rules
Update the out of the box CI mapping rules on ISAM (Secure: Access Control > Global Settings > Mapping Rules) with the contents of the rules in [mapping_rules](/mapping_rules).

#### HTML templates
Upload the HTML files and CSS rules from [html](/html) to ISAM via template files (Secure: Access Control > Global Settings > Template Files).

### Applying updates for IBM Verify to 9.0.5

If your ISAM is already setup with the CI Wizard with a reverse proxy configured, skip to [Step 1](#step-1-update-api-client-entitlements)

#### Step 0a: Run the Strong Authentication Wizard

In the ISAM LMI, navigate to **Connect: IBM Cloud Identity.**

Sign up for a free trial if you don't already have a Cloud Identity instance.

Scroll to the **Strong Authentication using IBM Cloud Identity APIs** section and click **Connect**.

Type your CI Administration Hostname in the **Administration Hostname** field, then click **Login to IBM Cloud Identity**.

Log in to your CI instance in the new tab. The tab will automatically close. Back on ISAM, click **Next**.

Once configuration is complete, take note of the policy names and endpoints.

#### Step 0b: Setup reverse proxy

In the ISAM LMI, navigate to **Secure: Web Settings > Manage > Runtime Component**, and run the Configure wizard.

Navigate to **Secure: Web Settings > Manage > Reverse Proxy**, and create a new instance.

Open the ISAM CLI and run the AAC configuration command

    isam> isam aac config
    
    Security Access Manager Autoconfiguration Tool Version 9.0.5.0 [20180530-2317]

    Select/deselect the capabilities you would like to configure by typing its number. Press enter to continue: 
    [ X ] 1. Context-based Authorization
    [ X ] 2. Authentication Service
    [ X ] 3. API Protection

    <enter>
    
    Press 1 for Next, 2 for Previous, 3 to Repeat, C to Cancel: 1
    Advanced Access Control Local Management Interface hostname: 168.20.0.31
    Advanced Access Control Local Management Interface port [443]: 443
    Advanced Access Control administrator user ID [admin]: admin
    Advanced Access Control administrator password: <password>
    Testing connection to https://168.20.0.31:443/.
    SSL certificate information:
      ...
    SSL certificate fingerprints:
      ...

    SSL certificate data valid (y/n): y
    Press 1 for Next, 2 for Previous, 3 to Repeat, C to Cancel: 1
    Security Access Manager Appliance Local Management Interface hostname: 168.20.0.31
    Security Access Manager Appliance Local Management Interface port [443]: 443
    Security Access Manager Appliance administrator user ID [admin]: admin
    Security Access Manager Appliance administrator password: <password>
    Testing connection to https://168.20.0.31:443/.
    SSL certificate information:
      ...
    SSL certificate fingerprints:
      ...

    SSL certificate data valid (y/n): y
    Instance to configure:
      1. default
      2. Cancel
    Enter your choice [1]: 1
    Press 1 for Next, 2 for Previous, 3 to Repeat, C to Cancel: 1
    Security Access Manager administrator user ID [sec_master]: sec_master
    Security Access Manager administrator password: <password>
    Security Access Manager Domain Name [Default]: Default
    Press 1 for Next, 2 for Previous, 3 to Repeat, C to Cancel: 1
    Advanced Access Control runtime listening interface hostname: localhost
    Advanced Access Control runtime listening interface port: 443
    Select the method for authentication between WebSEAL and the Advanced Access Control runtime listening interface: 
      1. Certificate authentication
      2. User-id/password authentication
    Enter your choice [1]: 2  
    Advanced Access Control runtime listening interface user ID: easuser
    Advanced Access Control runtime listening interface password: <password, normally passw0rd by default>
    Testing connection to https://localhost:443.
    Connection completed.
    SSL certificate information:
      ...
    SSL certificate fingerprints:
      ...

    SSL certificate data valid (y/n): y
    Automatically add CA certificate to the key database (y/n): y
    Restarting the WebSEAL server...
    Press 1 for Next, 2 for Previous, 3 to Repeat, C to Cancel: 1
    Gathering properties to automatically configure: RTSS cluster, RBA POP
    Gathering properties to automatically configure: Authentication service mappings
    Press 1 for Next, 2 for Previous, 3 to Repeat, C to Cancel: 1
    The following files are available on the Security Access Manager Appliance. Choose one for the '400 Bad Request' response page.
       1. oauth_template_rsp_400_bad_request.html
       2. oauth_template_rsp_401_unauthorized.html
       3. oauth_template_rsp_502_bad_gateway.html
    Enter your choice [1]: 1
    The following files are available on the Security Access Manager Appliance. Choose one for the '401 Unauthorized' response page.
       1. oauth_template_rsp_400_bad_request.html
       2. oauth_template_rsp_401_unauthorized.html
       3. oauth_template_rsp_502_bad_gateway.html
    Enter your choice [2]: 2
    The following files are available on the Security Access Manager Appliance. Choose one for the '502 Bad Gateway' response page.
       1. oauth_template_rsp_400_bad_request.html
       2. oauth_template_rsp_401_unauthorized.html
       3. oauth_template_rsp_502_bad_gateway.html
    Enter your choice [3]: 3
    Press 1 for Next, 2 for Previous, 3 to Repeat, C to Cancel: 1
    The junction /mga contains endpoints that require Authorization HTTP header to be forwarded to the backend server.
    Do you want to enable this feature? [y|n]? y

    URLs allowing unauthenticated access:
       ...

    Press 1 for Next, 2 for Previous, 3 to Repeat, C to Cancel: 1
    -----------------------------------------------
    Planned configuration steps:

    A junction to the Security Access Manager server will be created at /mga.

    The POP oauth-pop will be created.
    The POP rba-pop will be created.

    ACLs denying access to all users will be attached to:
       ...

    Press 1 for Next, 2 for Previous, 3 to Repeat, C to Cancel: 1


    Beginning configuration...
    ...

    Restarting the WebSEAL server...
    Configuration complete.


#### Step 1: Update API Client entitlements

CI API Client entitlements were changed after 9.0.5 shipped. The wizard will still successfully create an API Client, but it needs to be updated.

Navigate to the API Client configuration on your CI instance:

https://<administration_hostname>/ui/admin/settings?tab=api-access&subTab=api-clients

Select the API Client with the name **ISAM ApiClient <administration_hostname>**, then select the Edit button at the end of the row.

Ensure the following entitlements are checked:

* Authenticate any user
* Manage authenticator configuration (NEW)
* Manage authenticator registrations for all users (NEW)
* Manage second-factor authentication enrollment for all users
* Manage users and groups
* Read authenticator registrations for all users (NEW)
* Read second-factor authentication enrollment for all users
* Read users and groups

Before saving the entitlement changes, copy the **Client ID** and **Secret**. These are needed by the next step.

Click Save.

#### Step 2: Create Authenticator Client

Similar to an API Client, we also need to configure an Authenticator client. When authenticator registration is kicked off, an authenticator client must be chosen. The authenticator client is the point at which common configuration is saved, such as code and token lifetimes. 

As of writing (Oct 2018), there is no UI for authenticator clients. Instead you can create one via curl. First we need to get an access token using the API Client ID and secret.

Copy the client ID and secret from the previous step into the curl below.

    curl -X POST 'https://<administration_hostname>/v1.0/endpoint/default/token' \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -d 'grant_type=client_credentials&client_id=<CLIENT_ID>&client_secret=<CLIENT_SECRET>&scope=openid'
    
Take note of the access token in the response.

    {
      "access_token": "...",
      "scope": "openid",
      "grant_id": "...",
      "id_token": "...",
      "token_type": "Bearer",
      "expires_in": 7199
    }

Copy the access token into the curl below.

    curl -X POST https://jasmsmit.ice.ibmcloud.com/v1.0/authenticators/clients \
      -H 'Accept: application/json' \
      -H 'Authorization: Bearer PJa06jQViqZivoPXb3QRstWCriYYikRNP8Yt00RH' \
      -H 'Content-Type: application/json' \
      -d '{
      "authorizationCodeLifetime": 120,
      "enabled": true,
      "name": "VerifyAuthenticator",
      "refreshTokenLifetime": 63115200,
      "accessTokenLifetime": 3600
    }'

Take note of the ID in the response.

    {
        "authorizationCodeLifetime": 120,
        "name": "VerifyAuthenticator",
        "refreshTokenLifetime": 63115200,
        "id": "bee08271-6874-4a85-a353-4822d1bf9eae",
        "enabled": true,
        "accessTokenLifetime": 3600
    }

#### Step 2: Update ISAM policies

Now that we have an authenticator client ID, we can update the ISAM Cloud Identity policies configured via the wizard.

In the ISAM LMI navigate to **Secure: Access Control > Policy > Authentication.**

Select one of the Cloud Identity policies, then click **Edit**. In the workflow steps section, click the properties icon next to the mechanism name.

Check **Pass** next to the property **verifyClientId**, and copy the authenticator client ID into the value.

Click **OK** then **Save**. Repeat for the other policy. Deploy the changes.

Note: The User Self Care policy has two mechanisms. Add **verifyClientId** to both mechanisms.

#### Step 3: Update template pages

Navigate to **Secure: Access Control > Global Settings > Template Files.**

Select the **C** folder, then click **Manage > Import Zip**

Select **C.zip** (downloaded from [html](/html)) then click **Import**.

#### Step 4: Update ISAM mapping rules

Navigate to **Secure: Access Control > Global Settings > Mapping Rules.**

Replace **CI_Authentication_Rule**, **CI_Common**, **CI_Self_Care_Rule** with the files from [mapping_rules](/mapping_rules).

Import **ci_enrollment_methods.js** with the name **CI_Enrollment_Methods** and category **InfoMap**.

Deploy pending changes.

Now IBM Verify should be available in the authentication and USC policies (endpoints from the end of the wizard).

# License
```
Copyright 2018 International Business Machines

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

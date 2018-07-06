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

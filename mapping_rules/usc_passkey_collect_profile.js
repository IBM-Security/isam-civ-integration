importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importPackage(Packages.com.ibm.security.access.scimclient);
importMappingRule("BranchingHelper");
importMappingRule("USC_Common");

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

IDMappingExtUtils.traceString("Entry USC_Passkey_CollectProfile.js");

// Should we always request the password at this step, or wait until the user
// enrolls a passkey first.
var alwaysGetPassword = false;

var errors = [];
var missing = [];
var rc = true;

// Check if this is our first iteration. We don't want to return
// errors / attempt SCIM update on first iteration.
var first = false;

if (state.get("passkeyCollectProfileFirst") == null) {
  first = true;
  state.put("passkeyCollectProfileFirst", "false");
  rc = false;
}

// Get the email address.
function getEmail(){
    var sessionUsername = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username");
    var email = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "email");

    IDMappingExtUtils.traceString("Loaded username: "+sessionUsername);
    IDMappingExtUtils.traceString("Loaded email: "+email);

    // MAC OTP will leave username but not email populated. Reset username now because we want it to be set to
    // the real username, not the email, later.
    if (sessionUsername && !email) {
        IDMappingExtUtils.traceString("Setting urn:ibm:security:asf:response:token:attributes:username: null");
        IDMappingExtUtils.traceString("Setting urn:ibm:security:asf:response:token:attributes:email: "+sessionUsername);

        context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", null);
        context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "email", sessionUsername);
    }

    return sessionUsername||email;
}

var email = getEmail();
macros.put("@EMAIL@", email);

// Load the browsers reported UVPA capability.
var uvpaCapable = state.get("uvpaCapable");
IDMappingExtUtils.traceString("Loaded uvpaCapable: "+uvpaCapable);
macros.put("@UVPA_CAPABLE@", jsString(uvpaCapable));

// Send to the browser whether the profile page should always prompt for a password.
macros.put("@ALWAYS_GET_PASSWORD@", jsString(alwaysGetPassword));

var username = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "username"));
var firstName = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "firstName"));
var surname = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "surname"));
if (null == username || username.length == 0) {
    missing.push("User Name");
    rc = false;
}
if (null == firstName || firstName.length == 0) {
    missing.push("First Name");
    rc = false;
}
if (null == surname || surname.length == 0) {
    missing.push("Last Name");
    rc = false;
}

// Check that the passwords are present and match.
var password = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "password"));
var passwordConfirm = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "passwordConfirm"));

if ((alwaysGetPassword || uvpaCapable == false) && (null == password || password.length == 0)) {
    missing.push("Password");
    rc = false;
}
if (password != passwordConfirm) {
    errors.push("Passwords do not match.");
    rc = false;
}

//Convert the request parameters into SCIM JSON.
var scimSkeleton = {
  "schemas":[
    "urn:ietf:params:scim:schemas:core:2.0:User",
    "urn:ietf:params:scim:schemas:extension:isam:1.0:User"
  ],
  "userName": "",
  "emails": [],
  "name": {
    "givenName": "",
    "familyName": ""
  },
  "urn:ietf:params:scim:schemas:extension:isam:1.0:User": {
    "identity": "",
    "accountValid": true,
    "passwordValid": false
  }
};

function createScimJson() {
    var scim = scimSkeleton;
    scim.emails.push({
        "type": "work",
        "value": jsString(email)
    });
    scim.userName = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "username"));
    scim.name.givenName = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "firstName"));
    scim.name.familyName = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "surname"));
    scim["urn:ietf:params:scim:schemas:extension:isam:1.0:User"]["identity"] = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "username"));
        
    if (password != null && password != "") {
        scim["urn:ietf:params:scim:schemas:extension:isam:1.0:User"]["password"] = password;
        scim["urn:ietf:params:scim:schemas:extension:isam:1.0:User"]["passwordValid"] = true;

        var scimClone = deepcopy(scim);
        scimClone["urn:ietf:params:scim:schemas:extension:isam:1.0:User"]["password"] = "****";
        IDMappingExtUtils.traceString("SCIM JSON: "+JSON.stringify(scimClone));
    } else {
        IDMappingExtUtils.traceString("SCIM JSON: "+JSON.stringify(scim));
    }

    return scim;
}

// Post the JSON to the SCIM API endpoint.
if (rc == true) {
    var scimJson = createScimJson();

    var resp = ScimClient.httpPost(scimConfig, "/Users", JSON.stringify(scimJson));
    if (resp == null) {
        // Something went wrong.
        rc = false;
        errors.push("An error occurred contacting the SCIM endpoint.");
        errors.push("RESP is null!");

    } else {
        IDMappingExtUtils.traceString("SCIM resp.getCode(): "+resp.getCode());
        IDMappingExtUtils.traceString("SCIM resp.getBody(): "+resp.getBody());

        if (resp.getCode() == 201) {
            // success!
            rc = true;

        } else {
            if (resp.getCode() == 409) {
                errors.push("Account could not be created: user name is already in use.")
            }

            var respJson = JSON.parse(resp.getBody());
            if (respJson && respJson.detail) {
                errors.push("SCIM API error: "+respJson.detail);
            }

            rc = false;
        }

    }
}

var errorString = buildErrorString(errors, missing);
if (!first && errorString.length != 0) {
    macros.put("@ERROR_MESSAGE@", errorString);
}

if (rc == true) {
    // Set these values in the state so they can be displayed on the success page.
    state.put("username", scimJson["userName"]);
    state.put("firstName", scimJson["name"]["givenName"]);

    // Save in the state whether we have already collected the password, so we don't
    // prompt the user to save password again if they skip passkey reg.
    state.put("passCollected", password != null && password != "");

    // Clear out the email now.
    context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "email", null);
}

success.setValue(rc);

IDMappingExtUtils.traceString("Exit USC_Passkey_CollectProfile.js");

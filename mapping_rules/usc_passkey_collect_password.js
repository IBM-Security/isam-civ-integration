importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importPackage(Packages.com.ibm.security.access.scimclient);
importMappingRule("USC_Common");

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

IDMappingExtUtils.traceString("Entry USC_Passkey_CollectPassword.js");

var errors = [];
var missing = [];
var rc = true;

// Check if this is our first iteration. We don't want to return
// errors / attempt SCIM update on first iteration.
var first = false;

if (state.get("passkeyCollectPasswordFirst") == null) {
    first = true;
    state.put("passkeyCollectPasswordFirst", "false");
    rc = false;
}

var username = state.get("username");
var id = ScimClient.computeIDForUsername(username);
IDMappingExtUtils.traceString("Loaded SCIM user/id: "+username+"/"+id);

//Check that the passwords are present and match.
var password = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "password"));
var passwordConfirm = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "passwordConfirm"));
var httpMethod = context.get(Scope.REQUEST, "urn:ibm:security:asf:request", "method");

if (null == password || password.length == 0) {
    missing.push("Password");
    rc = false;
} else if (password != passwordConfirm) {
    errors.push("Passwords do not match.");
    rc = false;
} else if (httpMethod != "POST" && httpMethod != "PUT") {
    errors.push("Unsupported method.");
    rc = false;
}

var patchJson = {
  "schemas":[
    "urn:ietf:params:scim:api:messages:2.0:PatchOp"
  ],
  "Operations":[
    {
      "op":    "add",
      "value": {
        "urn:ietf:params:scim:schemas:extension:isam:1.0:User": {
          "passwordValid": true,
          "password": password
        }
      }
    }
  ]
};

if (rc == true) {

    var resp = ScimClient.httpPatch(scimConfig, "/Users/"+id, JSON.stringify(patchJson));
    if (resp == null) {

        // Something went wrong.
        rc = false;
        errors.push("An error occurred contacting the SCIM endpoint.");
        IDMappingExtUtils.traceString("Response is null!");

    } else {
        IDMappingExtUtils.traceString("SCIM resp.getCode(): "+resp.getCode());
        IDMappingExtUtils.traceString("SCIM resp.getBody(): "+resp.getBody());

        if (resp.getCode() == 200) {
            IDMappingExtUtils.traceString("Successfully changed password.");
            rc = true;

        } else {
            IDMappingExtUtils.traceString("Failed to change password.");

            var respJson = JSON.parse(resp.getBody());
            if (respJson && respJson.detail) {
                errors.push("SCIM API error: "+respJson.detail);
            } else {
                errors.push("An internal error occurred.");
            }

            rc = false;
        }
    }
}

var errorString = buildErrorString(errors, missing);
if (!first && errorString.length != 0) {
  macros.put("@ERROR_MESSAGE@", errorString);
}

success.setValue(rc);

IDMappingExtUtils.traceString("Exit USC_Passkey_CollectPassword.js");

/*********************************************************************
 * Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.
 *
 *   Licensed Materials - Property of IBM
 *   (C) Copyright IBM Corp. 2016, 2021. All Rights Reserved
 *
 *   US Government Users Restricted Rights - Use, duplication, or
 *   disclosure restricted by GSA ADP Schedule Contract with
 *   IBM Corp.
 *********************************************************************/

importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importPackage(Packages.com.ibm.security.access.scimclient);

IDMappingExtUtils.traceString("entry USC_PasswordReset_CollectPassword.js");

var errors = [];
var missing = [];
var rc = true;

var first = false;

if (state.get("first_collectPassword") == null) {
  first = true;
  state.put("first_collectPassword", "false");
  rc = false;
}

var scimConfig = context.get(Scope.SESSION, "urn:ibm:security:asf:policy", "scimConfig");

var username = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username");
var id = ScimClient.computeIDForUsername(username);
IDMappingExtUtils.traceString("Loaded SCIM user/id: "+username+"/"+id);

/*
 * Check that the passwords are present and match.
 */

function utf8decode(value) {
  if (value == null || value.length == 0) return "";
  return decodeURIComponent(escape(value));
}

var password = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "password"));
var passwordConfirm = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "passwordConfirm"));
var httpMethod = context.get(Scope.REQUEST, "urn:ibm:security:asf:request", "method");

if (null == password || password.length == 0) {
  missing.push("password");
  rc = false;
} else if (password != passwordConfirm) {
  errors.push("Passwords do not match.");
  rc = false;
} else if (httpMethod != "POST" && httpMethod != "PUT") {
  errors.push("Unsupported method.");
  rc = false;
}

/*
 * Get the SCIM user.
 */

function getUser(id) {
  var resp = ScimClient.httpGet(scimConfig, "/Users/"+id);
  var json = null;

  if (resp == null) {
    // Something went wrong.
    rc = false;
    errors.push("An error occurred contacting the SCIM endpoint.");

  } else {
    IDMappingExtUtils.traceString("SCIM resp.getCode(): "+resp.getCode());
    IDMappingExtUtils.traceString("SCIM resp.getBody(): "+resp.getBody());

    if (resp.getCode() == 200) {
      // success!
      rc = true;
    } else {
      var respJson = JSON.parse(resp.getBody());
      if (respJson && respJson.detail) {
        errors.push("SCIM API error: "+respJson.detail);
      } else {
        errors.push("An internal error occurred.");
      }

      rc =false;
    }
    json = JSON.parse(resp.getBody());
  }

  return json;
}


var scimJson = rc ? getUser(id) : null;

var patchJson = {
  "schemas":[
    "urn:ietf:params:scim:api:messages:2.0:PatchOp"
  ],
  "Operations":[
    {
      "op":    "replace",
      "path":  "password",
      "value": password
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

/*
 * Handle errors.
 */

function buildErrorString(errors) {
  var errorString = "";

  if (missing.length != 0) {
    errorString += "Missing required field(s): "+missing;
  }

  for (var error in errors) {
    if (errorString != "") errorString += "   ";
    errorString += "Error: "
    errorString += errors[error];
  }
  return errorString;
}

var errorString = buildErrorString(errors);
if (!first && errorString.length != 0) {
  macros.put("@ERROR_MESSAGE@", errorString);
}

if (rc == true) {
  /*
   * Set these values in the credential so they can be displayed on the success page.
   */
  context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", scimJson["userName"]);
  context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "firstName", scimJson["name"]["givenName"]);
}

/*
 * Done!
 */

success.setValue(rc);

IDMappingExtUtils.traceString("exit USC_PasswordReset_CollectPassword.js");

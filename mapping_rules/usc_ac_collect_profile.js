/*********************************************************************
 * Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.
 *
 *   Licensed Materials - Property of IBM
 *   (C) Copyright IBM Corp. 2016. All Rights Reserved
 *
 *   US Government Users Restricted Rights - Use, duplication, or
 *   disclosure restricted by GSA ADP Schedule Contract with
 *   IBM Corp.
 *********************************************************************/

importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importPackage(Packages.com.ibm.security.access.scimclient);

IDMappingExtUtils.traceString("entry USC_CreateAccount_CollectProfile.js");

var errors = [];
var missing = [];
var rc = true;

var first = false;
var scimConfig = context.get(Scope.SESSION, "urn:ibm:security:asf:policy", "scimConfig");

function utf8decode(value) {
  if (value == null || value.length == 0) return "";
  return decodeURIComponent(escape(value));
}

function deepcopy(obj) {
  if (null == obj || "object" != typeof obj) return obj;
  var copy = obj.constructor();
  for (var attr in obj) {
    if (obj.hasOwnProperty(attr)) copy[attr] = obj[attr];
  }
  return copy;
}

/*
 * Get the email address.
 */

function getEmail(){
  var username = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username");
  var email = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "email");

  IDMappingExtUtils.traceString("Loaded urn:ibm:security:asf:response:token:attributes:username: "+username);
  IDMappingExtUtils.traceString("Loaded urn:ibm:security:asf:response:token:attributes:email: "+email);

  /*
   * MAC OTP will leave username but not email populated.
   */

  if (username && !email) {
    IDMappingExtUtils.traceString("Setting urn:ibm:security:asf:response:token:attributes:username: null");
    IDMappingExtUtils.traceString("Setting urn:ibm:security:asf:response:token:attributes:email: "+username);

    context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", null);
    context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "email", username);

    first = true;
  }

  return username||email;
}

var email = getEmail();
macros.put("@EMAIL@", email);

/*
 * Check that the passwords are present and match.
 */

var password = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "password"));
var passwordConfirm = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "passwordConfirm"));

if (null == password || password.length == 0) {
  missing.push("password");
  rc = false;
} else if (password != passwordConfirm) {
  errors.push("Passwords do not match.");
  rc = false;
}

/*
 * Convert the request parameters into SCIM JSON.
 */

var enterpriseSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
var coreSchema = "urn:ietf:params:scim:schemas:core:2.0:User";

var scimSkeleton = {
  "schemas":[
    coreSchema,
    enterpriseSchema
  ]
};

/*
 * This array contains the mappings of all request parameters to SCIM JSON parameters.
 */

//  Parameter         [ key1, key2 ]                        Required Default isBoolean
var attrToScim = [
  [ "username",       ["userName"],                           true,  null,    false    ],
  [ "displayName",    ["displayName"],                        true,  null,    false    ],
  [ "firstName",      ["name", "givenName"],                  true,  null,    false    ],
  [ "surname",        ["name", "familyName"],                 true,  null,    false    ],
  [ "title",          ["title"],                              true,  null,    false    ],
  [ "addressType",    ["addresses", "type"],                  true,  "work",  false    ],
  [ "address",        ["addresses", "formatted"],             true,  null,    false    ],
  [ "streetAddress",  ["addresses", "streetAddress"],         true,  null,    false    ],
  [ "postcode",       ["addresses", "postalCode"],            true,  null,    false    ],
  [ "emailType",      ["emails", "type"],                     true,  "work",  false    ],
  [ "email",          ["emails", "value"],                    true,  null,    false    ],
  [ "password",       ["password"],                           true,  null,    false    ],
  [ "language",       ["preferredLanguage"],                  false, "en-us", false    ],
  [ "employeeNumber", [enterpriseSchema, "employeeNumber"],   true,  null,    false    ],
  [ "department",     [enterpriseSchema, "department"],       true,  null,    false    ],
  [ "organization",   [enterpriseSchema, "organization"],     true,  null,    false    ]
];

// Convenience enum-like structure for accessing attrToScim
var attrToScimMap = {
  ATTR: 0, KEYS: 1, REQ: 2, DEF: 3, BOOL: 4
}

// These attributes must be sent as an array - even though the contain a single value.
var multiValueAttrs = [
  "addresses", "emails"
];

/*
 * Helper function to perform multi-key level deep setting.
 * Think of it as shorthand for:
 * hash[keys[0]][keys[1]] ... [keys[n]] = value;
 *
 * Warning: If at any level key[n] is found to not have an
 * object type value, it will be overwritten with a new
 * object.
  * 
 * @param row The element from attrToScim array.
 * @param value  The value to set.
 * @param hash{} The associative array to modify.
 */
function setInHash(row, value, hash) {
  if (hash == null) return;
  var hashOrig = hash;
  var key = 0;
  var keys = row[attrToScimMap.KEYS];
  
  if (row[attrToScimMap.BOOL]) {
     value = (value == "true"); 
  }
  
  while(key < keys.length) {
    if (!(keys[key] in hash) || hash[keys[key]].constructor != Object) hash[keys[key]] = {};
    if (key == keys.length-1) {
      hash[keys[key]] = value;
    } else {
      hash = hash[keys[key]];
    }
    key++;
  }
  hash = hashOrig;
};

function createScimJson() {
  var scim = scimSkeleton;

  for (var attr in attrToScim) {
    var a = attrToScim[attr];

    var val = "";

    if ("email" == a[attrToScimMap.ATTR]) {
      // email is special and should not come from the request
      val = ""+email;
    } else {
      // Get the value from the request
      val = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", a[attrToScimMap.ATTR]));
    }

    // No value? Try the default.
    if (val == null || val == "") {
      val = a[attrToScimMap.DEF];
    }

    // Still no value? Check if it is required.
    if (val == null || val == "") {
      if (a[attrToScimMap.REQ]) {
        if (-1 == missing.indexOf(a[attrToScimMap.ATTR])) {
          missing.push(a[attrToScimMap.ATTR]);
        }
        rc = false;
      }
      continue;
    }

    if (-1 == a[attrToScimMap.ATTR].indexOf("password")) {
      var macroName = "@"+a[attrToScimMap.ATTR].toUpperCase()+"@";
      IDMappingExtUtils.traceString("Setting macro: "+macroName+" = "+val);
      macros.put(macroName, val);
    }

    if(a[attrToScimMap.ATTR] !== "password") {
      IDMappingExtUtils.traceString("SCIM "+a[attrToScimMap.ATTR]+" = "+val);
    } else {
      IDMappingExtUtils.traceString("SCIM "+a[attrToScimMap.ATTR]+" = ****");
    }
    setInHash(a, ""+val, scim)

  }

  // Convert the multi-value attributes to arrays
  for (var attr in multiValueAttrs) {
    if (multiValueAttrs[attr] in scim) scim[multiValueAttrs[attr]] = [ scim[multiValueAttrs[attr]] ];
  }

  var scimClone = deepcopy(scim);
  scimClone["password"] = "****";
  IDMappingExtUtils.traceString("SCIM JSON: "+JSON.stringify(scimClone));

  return scim;
}

var scimJson = createScimJson();

/*
 * Post the JSON to the SCIM API endpoint.
 */

if (rc == true) {

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

IDMappingExtUtils.traceString("exit USC_CreateAccount_CollectProfile.js");
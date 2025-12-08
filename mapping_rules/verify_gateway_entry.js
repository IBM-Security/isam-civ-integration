importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.OAuthMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.registrations.MechanismRegistrationHelper);
importClass(Packages.com.ibm.security.access.user.UserLookupHelper);
importClass(Packages.com.ibm.security.access.scimclient.ScimClient);
importClass(Packages.com.tivoli.am.fim.base64.BASE64Utility);
importClass(Packages.com.tivoli.am.fim.authsvc.local.client.AuthSvcClient);

/**
 * Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.
 *
 * This mapping rule allows a IBM Verify Gateway user to authenticate using
 * on-premise registered authentication methods.
 *
 * Updates to this file will also be made available at:
 *      https://github.com/IBM-Security/verify-access-aac-mapping-rules
 *
 */

var PERSISTENT_CACHE_TIMEOUT = 300; // 5 mins

/*
 * These parameters likely need to be changed per deployment
 */
var POINT_OF_CONTACT_URL = "https://www.mmfa.ibm.com";

//
// The set of permitted IVIA OAuth clients that can invoke this Infomap/policy.
// You need to put your OAuth client in this list, or create one called VerifyGatewayClient.
//
var allowedClients = [ "VerifyGatewayClient" ];

//
// This variable determines what group(s) an end-user must be in for a particular allowedClient.
// It can be set to null, in which case no group checking is performed.
//
//var clientToAllowedGroups = {
//  "VerifyGatewayClient": [ "windowsgroup" ]
//}
var clientToAllowedGroups = null;

//
// Simple config used to control which IVIA 2FA methods are allowed to be returned
//
var ENABLED_2FA_METHODS = {
        totp: true,
        emailotp: true,
        smsotp: true,
        mobilepush: true
}

//
// Special config for determining which IBM Verify mobile push signature methods
// will be returned.
//
// If ENABLED_2FA_METHODS.mobilepush is true, this will enable specific types
// there is a special case if "bestAvailable" is true, then userPresence
// and fingerprint flags are ignored. If a user has fingerprint signature
// capabilities, only those will be returned, otherwise any available userPresence
// capabilities will be returned.
//
// If you want "everything", set bestAvailable to false, and the others to true.
//
var ENABLED_MOBILE_PUSH_METHODS = {
        bestAvailable: false,
        userPresence: true,
        fingerprint: true
}

//
// These are policy URIs defined as per the MMFA cookbook. Your environment might use
// something different, so check the configuration and adjust here as needed.
//
var AUTHSVC_POLICYURI_RESPONSE_USERPRESENCE = "urn:ibm:security:authentication:asf:verify_gateway_mmfa_userpresence_resp";
var AUTHSVC_POLICYURI_RESPONSE_FINGERPRINT = "urn:ibm:security:authentication:asf:verify_gateway_mmfa_fingerprint_resp";

/*
 * Utility functions for temporary state storage.
 */
var AuthSvcState = {
    /*
     * Uses IDMappingExtCache to store session state objects.
     * Note that keys are hashed because they can be too long.
     */
    "shakey": function(s) {
        return BASE64Utility.encode(OAuthMappingExtUtils.SHA512Sum(s), false);
    },

    "storeState": function(k,o) {
        let cache = IDMappingExtUtils.getIDMappingExtCache();

        let jsk = this.shakey(k);

        let strval = JSON.stringify(o);

        cache.put(jsk, strval, PERSISTENT_CACHE_TIMEOUT);
    },

    "getState": function(k) {
        let cache = IDMappingExtUtils.getIDMappingExtCache();
        let result = null;

        let jsk = this.shakey(k);
        let jstr = cache.get(jsk);
        if (jstr != null) {
            result = JSON.parse(jstr);
        }
        return result;
    },

    "getAndRemoveState": function(k) {
        let cache = IDMappingExtUtils.getIDMappingExtCache();
        let result = null;

        let jsk = this.shakey(k);
        let jstr = cache.getAndRemove(jsk);
        if (jstr != null) {
            result = JSON.parse(jstr);
        }

        return result;
    }
};

//
// Utility functions
//
function debugLog(str) {
    if (typeof (console) != "undefined") {
        console.log(str);
    } else {
        IDMappingExtUtils.traceString(str);
    }
}

function createUUID() {
    return ''+OAuthMappingExtUtils.createUUID();
}

function emptyIfNull(s) {
    return (s == null ? '' : ''+s);
}

function arrayToLogStr(a) {
    let result = null;
    if (a != null) {
        let result = '[';
        for (let i = 0; i < a.length; i++) {
            result += a[i];
            if (i < (a.length-1)) {
                result += ',';
            }
        }
        result += ']';
    }
    return result;
}

// Used for debugging
function dumpContext() {
    debugLog("request attributes: " +context.get(Scope.REQUEST, "urn:ibm:security:asf:request", "attributes"));
    debugLog("request headers: " +context.get(Scope.REQUEST, "urn:ibm:security:asf:request", "headers"));

    let cookieValues = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:headers", "cookie");
    debugLog("cookie headers: " + arrayToLogStr(cookieValues));

    let parameters = context.get(Scope.REQUEST, "urn:ibm:security:asf:request", "parameters");
    debugLog("request parameters: " +parameters);
    if (parameters != null) {
        for (let i = parameters.iterator(); i.hasNext();) {
            let paramName = i.next();
            let paramValues = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameters", paramName);
            debugLog("paramName: " + paramName + " paramValues: " + arrayToLogStr(paramValues));
        }
    }

    //debugLog("response attrs: " +context.get(Scope.SESSION, "urn:ibm:security:asf:response", "attributes"));
}

function throwSCIMError(methodName, errorText, httpStatusCode) {
    debugLog("throwSCIMError being called for methodName: " + methodName + " httpStatusCode: " + httpStatusCode +  " errorText: " + errorText);
    let msg = methodName + ": " + errorText;
    let code = "400";
    if (httpStatusCode != null && httpStatusCode != "") {
        code = httpStatusCode;
    }
    let e = {
        "httpStatusCode": code,
        "httpContentType": "application/scim+json",
        "status":code,
        "detail":msg,
        "schemas":["urn:ietf:params:scim:api:messages:2.0:Error"]
    };
    throw e;
}

function throwErrorWithCode(methodName, errorText, httpStatusCode) {
    debugLog("throwErrorWithCode being called for methodName: " + methodName + " errorText: " + errorText);
    let msg = methodName + ": " + errorText;
    throw {"httpStatusCode": httpStatusCode,"error":msg,"messageId":msg,"messageDescription":msg};
}

function throwError(methodName, errorText) {
    debugLog("throwError being called for methodName: " + methodName + " errorText: " + errorText);
    let msg = methodName + ": " + errorText;
    throw {"error":msg};
}

//
// Function which determines if a particular user is allowed to authenticate from the current client based on group memberships.
//
function checkUserAuthorization(currentClient, user) {
    let result = false;

    // if clientToAllowedGroups is null, or there is no entry for the current client, then by definition we are not doing group-based authorization
    if (clientToAllowedGroups == null || clientToAllowedGroups[currentClient] == null) {
        debugLog("checkUserAuthorization: no group access for client: " + currentClient + " Allowing access for user: " + user.getId());
        result = true;
    }

    if (!result) {
        // if any of the user's groups is in the allowed list of this client, permit
        let userGroups = user.getGroups();
        for (let i = 0; i < userGroups.length && result == false; i++) {
            if (clientToAllowedGroups[currentClient].indexOf(''+userGroups[i]) >= 0) {
                debugLog("checkUserAuthorization: client: " + currentClient + " Allowing access for user: " + user.getId() + " in group: " + userGroups[i]);
                result = true;
            }
        }
    }

    // if not permitted, log why, then throw an error
    if (!result) {
        debugLog("checkUserAuthorization: client: " + currentClient + " Denying access for user: " + user.getId() + " not in any allowed group: " + JSON.stringify(clientToAllowedGroups[currentClient]));
        throwErrorWithCode("checkUserAuthorization", "User not authorized", "401");
    }
}

function prepareUserResponse(user) {
    let u = {
            "id": "XXXX",
            "userName": "XXXX",
            "active": true,
            "emails": [],
            "phoneNumbers": [],
            "meta": {
              "created": "2019-01-01T00:00:000Z",
              "lastModified": "2019-01-01T00:00:000Z"
            },
            "name": {
                "formatted": "Firstname Surname",
                "familyName": "Surname",
                "givenName": "Firstname"
            },
            "urn:ietf:params:scim:schemas:extension:ibm:2.0:User": {
                "userCategory": "regular",
                "twoFactorAuthentication": false,
                "realm": "cloudIdentityRealm",
                "pwdChangedTime": "2019-01-01T00:00:000Z"
            }
            /*,
            "groups": [
                {
                    "displayName": "group1",
                    "id": "50DFJQ6C1T",
                    "$ref": "https://myidp.ice.ibmcloud.com/v2.0/Groups/50DFJQ6C1T"
                }
            ]
            */
    };
    u.id = ''+ScimClient.computeIDForUsername(user.getId());
    u.userName = ''+user.getId();

    // add email if we have it, and emailotp is enabled
    if (ENABLED_2FA_METHODS.emailotp) {
        let email = user.getAttribute("mail");
        if (email != null) {
            u.emails.push({"type":"work","value":''+email});
        }
    }

    // add phone number if we have it and smsotp is enabled
    if (ENABLED_2FA_METHODS.smsotp) {
        let phone = user.getAttribute("mobile");
        if (phone != null) {
            u.phoneNumbers.push({"type":"mobile","value":''+phone});
        }
    }

    // if the user is in any groups, add them. These might be used for radius server access policy
    var groups = user.getGroups();
    if (groups != null && groups.length > 0) {
        u["groups"] = [];
        for (let i = 0; i < groups.length; i++) {
            let groupId = ScimClient.computeIDForUsername(groups[i]);
            u.groups.push({"displayName":''+groups[i],"id":''+groupId,"$ref":''+groupId})
        }
    }

    return u;
}

function processUsersRequest(ulh, currentClient, uri) {
    // start with empty user search result
    let result = {"httpContentType":"application/scim+json","totalResults":0,
                "schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"Resources":[]};
    let regex = /^\/v2.0\/Users\?filter=userName eq "([^"]*)"$/;
    let m = unescape(uri).match(regex);
    if (m != null && m.length == 2) {
        let username = m[1];

        // lets see if we have this user
        debugLog("Attempting to lookup user: " + username);
        let user = ulh.getUser(username);
        if (user != null) {
            try {
                // perform authorizatin check - error thrown if this user is not allowed to be used from this client
                // in which case we wrap and re-throw as a SCIM error
                checkUserAuthorization(currentClient, user);
            } catch (e) {
                throwSCIMError("processUsersRequest", e.error, "401");
            }

            // populate skeleton user, then update with information from ldap user
            result.totalResults = 1;
            let u = prepareUserResponse(user);
            result.Resources.push(u);
        } else {
            debugLog("processUsersRequest: User not found: " + username);
        }
    } else {
        throwSCIMError("processUsersRequest", "Invalid uri", "400");;
    }

    return result;
}

function processUserLookup(ulh, currentClient, uri) {
    let result = {};

    let regex = /^\/v2.0\/Users\/(.*)$/;
    let m = unescape(uri).match(regex);
    if (m != null && m.length == 2) {
        let scimID = m[1];
        let user = ulh.getUser(ScimClient.computeUsernameFromID(scimID));
        if (user != null) {
            try {
                // perform authorizatin check - error thrown if this user is not allowed to be used from this client
                // in which case we wrap and re-throw as a SCIM error
                checkUserAuthorization(currentClient, user);
            } catch (e) {
                throwSCIMError("processUserLookup", e.error, "401");
            }
            result = prepareUserResponse(user);
        } else {
            throwSCIMError("processUserLookup", "User does not exist", "404");
        }
    } else {
        throwSCIMError("processUserLookup", "Invalid uri", "400");
    }

    return result;
}

function processFactorsLookup(ulh, currentClient, uri) {
    let result = {"total": 0,"factors":[],"count":200,"limit":200,"page":1};

    let regex = /^\/v2.0\/factors\?search=userId\s*=\s*"([^"]*)"$/;
    let m = unescape(uri).match(regex);
    if (m != null && m.length == 2) {
        let scimID = m[1];
        let username = ScimClient.computeUsernameFromID(scimID);
        let user = ulh.getUser(username);
        if (user != null) {
            // perform authorizatin check - error thrown if this user is not allowed to be used from this client
            checkUserAuthorization(currentClient, user);

            // if TOTP is enabled, and this user has TOTP, indicate that
            if (ENABLED_2FA_METHODS.totp) {
                let canDoTOTP = (IDMappingExtUtils.retrieveSecretKey("otpfed","jdbc_userinfo",username,"otp.hmac.totp.secret.key","urn:ibm:security:otp:hmac") != null);
                if (canDoTOTP) {
                    result.total++;
                    result.factors.push({
                        "id": scimID,
                        "userId": scimID,
                        "type": "totp",
                        "creationTime": "2019-01-01T00:00:00.000Z",
                        "updated": "2019-01-01T00:00:00.000Z",
                        "attempted": "2019-01-01T00:00:00.000Z",
                        "enabled": true,
                        "validated": true,
                        "attributes": {
                            "algorithm": "SHA1",
                            "digits": 6,
                            "period": 30
                        }
                    });
                }
            }
        } else {
            // just return an empty list for unknown user
            debugLog("processFactorsLookup: User not found: " + username);
        }
    } else {
        throwError("processFactorsLookup", "Invalid uri");
    }

    return result;
}

function processFactorsTOTPLookup(ulh, currentClient, uri) {
    /* subtly different from processFactorsLookup in response body and regex */
    var result = {"total": 0,"totp":[],"count":200,"limit":200,"page":1};

    var regex = /^\/v2.0\/factors\/totp\?search=userId\s*=\s*"([^"]*)"$/;
    var m = unescape(uri).match(regex);
    if (m != null && m.length == 2) {
        var scimID = m[1];
        var username = ScimClient.computeUsernameFromID(scimID);
        var user = ulh.getUser(username);
        if (user != null) {
            // perform authorizatin check - error thrown if this user is not allowed to be used from this client
            checkUserAuthorization(currentClient, user);

            // if TOTP is enabled, and this user has TOTP, indicate that
            if (ENABLED_2FA_METHODS.totp) {
                var canDoTOTP = (IDMappingExtUtils.retrieveSecretKey("otpfed", "jdbc_userinfo", username, "otp.hmac.totp.secret.key","urn:ibm:security:otp:hmac") != null);
                if (canDoTOTP) {
                    result.total++;
                    result.totp.push({
                        "id": scimID,
                        "userId": scimID,
                        "type": "totp",
                        "creationTime": "2019-01-01T00:00:00.000Z",
                        "updated": "2019-01-01T00:00:00.000Z",
                        "attempted": "2019-01-01T00:00:00.000Z",
                        "enabled": true,
                        "validated": true,
                        "attributes": {
                            "algorithm": "SHA1",
                            "digits": 6,
                            "period": 30
                        }
                    });
                }
            }
        } else {
            // just return an empty list for unknown user
            debugLog("processFactorsTOTPLookup: User not found: " + username);
        }
    } else {
        throwError("processFactorsTOTPLookup", "Invalid uri");
    }

    return result;
}

function processFactorsTOTPVerification(ulh, currentClient, uri, totp) {

    debugLog("processFactorsTOTPVerification called for uri: " + uri + " totp: " + totp);

    let result = null; // to eventually return a 204 on success
    let totpVerified = false;
    let regex = /^\/v2.0\/factors\/totp\/([^\/]*)$/;
    let m = unescape(uri).match(regex);
    if (m != null && m.length == 2) {
        let scimID = m[1];
        let username = ScimClient.computeUsernameFromID(scimID);
        let user = ulh.getUser(username);
        if (user != null) {

            // perform authorizatin check - error thrown if this user is not allowed to be used from this client
            checkUserAuthorization(currentClient, user);

            let body = {
                "PolicyId": "urn:ibm:security:authentication:asf:verify_gateway_totp",
                "username": ''+username,
                "otp": totp,
                "operation": "verify"
            };

            debugLog("processFactorsTOTPVerification AuthSvcClient sending to verify_gateway_totp: " + JSON.stringify(body));
            let authsvcResponseStr = AuthSvcClient.execute(JSON.stringify(body));
            debugLog("processFactorsTOTPVerification AuthSvcClient result: " + authsvcResponseStr);

            let authSvcResponse = JSON.parse(''+authsvcResponseStr);

            if (authSvcResponse.status == "success") {
                // success
                totpVerified = true;
            }
        }
    }
    if (!totpVerified) {
        let error = {"httpStatusCode":"400","messageId":"CSIBN0021E","messageDescription":"The verification attempt failed."};
        throw error;
    }
    return result;
}

function processFactorsMACOTPStart(ulh, currentClient, uri, deliveryType, deliveryAttribute) {
    let result = {};
    let body = {
        "PolicyId": "urn:ibm:security:authentication:asf:verify_gateway_macotp",
        "username": "transient",
        "deliveryType": "TBD"
    };

    if (uri == "/v2.0/factors/emailotp/transient/verifications") {
        body.deliveryType = "Email";
        body.emailAddress = deliveryAttribute;
    } else if (uri == "/v2.0/factors/smsotp/transient/verifications") {
        body.deliveryType = "SMS";
        body.mobileNumber = deliveryAttribute;
    } else 
        throwError("processFactorsMACOTPStart", "Invalid uri");{
    }

    debugLog("processFactorsMACOTPStart AuthSvcClient sending to verify_gateway_macotp: " + JSON.stringify(body));
    let authsvcResponseStr = AuthSvcClient.execute(JSON.stringify(body));
    debugLog("processFactorsMACOTPStart AuthSvcClient result: " + authsvcResponseStr);

    let authsvcResponse = JSON.parse(''+authsvcResponseStr);

    if (authsvcResponse.status == "pause") {
        let jsonBody = authsvcResponse.response;

        // store state information based on initial stateId of this policy invocation
        // that's because the stateid sent to the client in the factors-like response is
        // static for the lifetime of this attempt at MAC OTP, however the user may try
        // multiple times and each time the IVIA-based StateId will change
        let stateObj = {
                "stateId": jsonBody["stateId"]
        }
        AuthSvcState.storeState(jsonBody["stateId"] + "_StateObj", stateObj);

        // emailotp and smsotp are almost identical
        let now = new Date();
        // 5 minutes
        let expiry = new Date(now.getTime() + PERSISTENT_CACHE_TIMEOUT * 1000);

        let methodType = (uri == "/v2.0/factors/emailotp/transient/verifications" ? "emailotp" : "smsotp");

        // need to build a response similar to this one (captured from ISV)
        // response code 201 (Created)
        result = {
          "httpStatusCode": "201",
          "id": jsonBody["stateId"],
          "type": methodType,
          "created": now.toISOString(),
          "updated": now.toISOString(),
          "expiry": expiry.toISOString(),
          "state": "PENDING",
          "correlation": jsonBody["otp.user.otp-hint"],
          "attempts": 0,
          "retries": 4
        };

        if (methodType == "emailotp") {
            result["emailAddress"] = deliveryAttribute;
        } else {
            result["phoneNumber"] = deliveryAttribute;
        }
    } else {
        // response status not "pause"
        throwError("processFactorsMACOTPStart", "Bad AuthSvcClient response status: " + authsvcResponse.status);;
    }

    return result;
}

function processFactorsMACOTPSubmit(ulh, currentClient, uri, deliveryType, otp) {
    let result = null;

    // extract stateid from uri
    let otpVerified = false;
    let stateId = null;
    // this regexp matches both emailotp and smsotp transient verification URLs
    let regex = /^\/v2.0\/factors\/[^\/]*\/transient\/verifications\/([^\/]*)$/;
    let m = unescape(uri).match(regex);
    if (m != null && m.length == 2) {
        stateId = m[1];

        // retrieve state object - this is to get the "current" authsvc policy stateid
        let stateObj = AuthSvcState.getState(stateId + "_StateObj");
        if (stateObj == null || stateObj.stateId == null) {
            throwError("processFactorsMACOTPSubmit", "Unable to retrieve authsvc session state");
        }

        // now time to verify against IVIA
        let body = {
            "StateId": stateObj.stateId,
            "otp.user.otp": otp,
            "operation": "verify"
        };

        debugLog("processFactorsMACOTPSubmit AuthSvcClient sending to verify_gateway_macotp: " + JSON.stringify(body));
        let authsvcResponseStr = AuthSvcClient.execute(JSON.stringify(body));
        debugLog("processFactorsMACOTPSubmit AuthSvcClient result: " + authsvcResponseStr);

        let authsvcResponse = JSON.parse(''+authsvcResponseStr);

        if (authsvcResponse.status == "success") {
            // success - may as well remove state
            stateObj = AuthSvcState.getAndRemoveState(stateId + "_StateObj");
            otpVerified = true;
        } else if (authsvcResponse.status == "pause") {
            // probably an OTP entry error, need to retain updated stateId and return an error
            let jsonBody = authsvcResponse.response;
            stateObj["stateId"] = jsonBody.stateId;
            AuthSvcState.storeState(stateId + "_StateObj", stateObj);
        }
    }

    if (!otpVerified) {
        let error = {"messageId":"CSIBN0021E","messageDescription":"The verification attempt failed."};
        throw error;
    }

    return result;
}

function processAuthenticationMethodsSearch(ulh, currentClient, uri) {
    let result = {"total":0, "authnmethods": [],"count":200,"limit":200,"page":1};
    let regex = /^\/v1.0\/authnmethods\?search=owner\s*=\s*"([^"]*)"$/;
    let m = unescape(uri).match(regex);
    if (m != null && m.length == 2) {
        let scimID = m[1];
        let username = ScimClient.computeUsernameFromID(scimID);
        let user = ulh.getUser(username);
        if (user != null) {
            // perform authorizatin check - error thrown if this user is not allowed to be used from this client
            checkUserAuthorization(currentClient, user);

            // if TOTP is enabled, and this user has TOTP, indicate that
            if (ENABLED_2FA_METHODS.totp) {
                let canDoTOTP = (IDMappingExtUtils.retrieveSecretKey("otpfed","jdbc_userinfo",username,"otp.hmac.totp.secret.key","urn:ibm:security:otp:hmac") != null);
                if (canDoTOTP) {
                    result.total = 1;
                    result.authnmethods.push({
                        "owner": scimID,
                        "methodType": "totp",
                        "isValidated": true,
                        "creationTime": "2019-01-01T00:00:00.000Z",
                        "isEnabled": true,
                        "attributes": {
                            "period": 30,
                            "digits": 6,
                            "algorithm": "SHA1"
                        },
                        "id": scimID
                    });
                }
            }
        } else {
            debugLog("processAuthenticationMethodsSearch: User not found");
        }
    } else {
        throwError("processAuthenticationMethodsSearch", "Invalid uri");
    }
    return result;
}

function processAuthenticationMethodsTOTPSearch(ulh, currentClient, uri) {
    /* subtly different from processAuthenticationMethodsSearch in result body and regex */
    let result = {"total":0, "totp": [],"count":200,"limit":200,"page":1};
    let regex = /^\/v1.0\/authnmethods\/totp\?search=owner\s*=\s*"([^"]*)"$/;
    let m = unescape(uri).match(regex);
    if (m != null && m.length == 2) {
        let scimID = m[1];
        let username = ScimClient.computeUsernameFromID(scimID);
        let user = ulh.getUser(username);
        if (user != null) {
            // perform authorizatin check - error thrown if this user is not allowed to be used from this client
            checkUserAuthorization(currentClient, user);

            // if TOTP is enabled, and this user has TOTP, indicate that
            if (ENABLED_2FA_METHODS.totp) {
                let canDoTOTP = (IDMappingExtUtils.retrieveSecretKey("otpfed","jdbc_userinfo",username,"otp.hmac.totp.secret.key","urn:ibm:security:otp:hmac") != null);
                if (canDoTOTP) {
                    result.total = 1;
                    result.totp.push({
                        "owner": scimID,
                        "methodType": "totp",
                        "isValidated": true,
                        "creationTime": "2019-01-01T00:00:00.000Z",
                        "isEnabled": true,
                        "attributes": {
                            "period": 30,
                            "digits": 6,
                            "algorithm": "SHA1"
                        },
                        "id": scimID
                    });
                }
            }
        }
    } else {
        throwError("processAuthenticationMethodsTOTPSearch", "Invalid uri");
    }
    return result;
}

function processTOTPVerification(ulh, currentClient, uri, totp) {
    let result = {"messageId":"CSIBN0022I","messageDescription":"The authentication factor [TOTP] is verified."};
    let error = {"messageId":"CSIBN0021E","messageDescription":"The system cannot verify the authentication factor [TOTP]."};
    let totpVerified = false;
    let regex = /^\/v1.0\/authnmethods\/totp\/([^\/]*)$/;
    let m = unescape(uri).match(regex);
    if (m != null && m.length == 2) {
        let scimID = m[1];
        let username = ScimClient.computeUsernameFromID(scimID);
        let user = ulh.getUser(username);
        if (user != null) {
            // perform authorizatin check - error thrown if this user is not allowed to be used from this client
            checkUserAuthorization(currentClient, user);

            debugLog("Verifying TOTP for username: " + username + " totp: " + totp);

            let body = {
                "PolicyId": "urn:ibm:security:authentication:asf:verify_gateway_totp",
                "username": ''+username,
                "otp": totp,
                "operation": "verify"
            };

            debugLog("processTOTPVerification AuthSvcClient sending to verify_gateway_totp: " + JSON.stringify(body));
            let authsvcResponseStr = AuthSvcClient.execute(JSON.stringify(body));
            debugLog("processTOTPVerification AuthSvcClient result: " + authsvcResponseStr);

            let authSvcResponse = JSON.parse(''+authsvcResponseStr);

            if (authSvcResponse.status == "success") {
                // success
                totpVerified = true;
            }
        }
    }

    if (!totpVerified) {
        throw error;
    }
    return result;
}

function processUserAuthentication(ulh, currentClient, uri, username, pwd) {
    let result = {
        "httpContentType": "application/scim+json",
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:User"
        ],
        "id": "XXXXX"
    };

    let error = {
        "httpStatusCode": "400",
        "httpContentType": "application/scim+json",
        "schemas": [
            "urn:ietf:params:scim:api:messages:2.0:Error"
        ],
        "status": "400",
        "detail": "CSIAI0160E Authentication failed.",
        "scimType": "INVALID_CREDS"
    };

    let pwVerified = false;
    let user = ulh.getUser(username);
    if (user != null) {
        // perform authorizatin check - error thrown if this user is not allowed to be used from this client
        checkUserAuthorization(currentClient, user);

        //debugLog("Verifying password for username: " + username + " password: " + pwd);
        let isAuthenticated = user.authenticate(pwd);
        //debugLog("Password Valid: " + isAuthenticated);

        if (isAuthenticated) {
            // success
            pwVerified = true;
        }
    } else {
        debugLog("processUserAuthentication: unable to find user: " + username);
    }

    if (!pwVerified) {
        throw error;
    }

    result.id = ''+ScimClient.computeIDForUsername(username);
    return result;
}

function processMACOTPStart(ulh, currentClient, uri, deliveryType, deliveryAttribute) {
    let result = {};

    // now time to kick it off with IVIA
    let body = {
        "PolicyId": "urn:ibm:security:authentication:asf:verify_gateway_macotp",
        "username": 'transient',
        "deliveryType": 'TBD'
    };

    if (uri == "/v1.0/authnmethods/emailotp/transient/verification") {
        body.deliveryType = "Email";
        body.emailAddress = deliveryAttribute;
    } else if (uri == "/v1.0/authnmethods/smsotp/transient/verification") {
        body.deliveryType = "SMS";
        body.mobileNumber = deliveryAttribute;
    } else {
        let error = { "error": "processMACOTPStart bad uri provided" };
        throw error;
    }

    debugLog("processMACOTPStart AuthSvcClient sending to verify_gateway_macotp: " + JSON.stringify(body));
    let authsvcResponseStr = AuthSvcClient.execute(JSON.stringify(body));
    debugLog("processMACOTPStart AuthSvcClient result: " + authsvcResponseStr);

    let authsvcResponse = JSON.parse(''+authsvcResponseStr);

    if (authsvcResponse.status == "pause") {
        let jsonBody = authsvcResponse.response;

        // store state information based on initial stateId of this policy invocation
        // that's because the stateid sent to the client in the ISV-like response is
        // static for the lifetime of this attempt at MAC OTP, however the user may try
        // multiple times and each time the IVIA-based StateId will change
        let stateObj = {
                "stateId": jsonBody["stateId"]
        }
        AuthSvcState.storeState(jsonBody["stateId"] + "_StateObj", stateObj);

        // emailotp and smsotp are almost identical
        let now = new Date();
        // 5 minutes
        let expiry = new Date(now.getTime() + PERSISTENT_CACHE_TIMEOUT * 1000);

        let methodType = (uri == "/v1.0/authnmethods/emailotp/transient/verification" ? "emailotp" : "smsotp");

        // need to build a response similar to this one (captured from CI)
        // response code 202 (Accepted)
        result = {
          "httpStatusCode": "202",
          "owner": "unavailable",
          "transactionType": "transient",
          "maxTries": 5,
          "sentTo": deliveryAttribute,
          "methodType": methodType,
          "correlation": jsonBody["otp.user.otp-hint"],
          "creationTime": now.toISOString(),
          "expiryTime": expiry.toISOString(),
          "numberOfAttempts": 0,
          "id": jsonBody["stateId"]
        };
    } else {
        // response status not "pause"
        throwError("processMACOTPStart", "Bad AuthSvcClient response status: " + authsvcResponse.status);
    }

    return result;
}

function processMACOTPSubmit(ulh, currentClient, uri, deliveryType, otp) {
    let result = {"messageId":"CSIAH0620I","messageDescription":"The authentication attempt was successful."};

    // extract stateid from uri
    let otpVerified = false;
    let stateId = null;
    // this regexp matches both emailotp and smsotp transient verification URLs
    let regex = /^\/v1.0\/authnmethods\/[^\/]*\/transient\/verification\/([^\/]*)$/;
    let m = unescape(uri).match(regex);
    if (m != null && m.length == 2) {
        stateId = m[1];

        // retrieve state object - this is to get the "current" authsvc policy stateid
        let stateObj = AuthSvcState.getState(stateId + "_StateObj");
        if (stateObj == null || stateObj.stateId == null) {
            throwError("processMACOTPSubmit", "Unable to retrieve authsvc session state");
        }

        // now time to verify against IVIA
        let body = {
            "StateId": stateObj.stateId,
            "otp.user.otp": otp,
            "operation": "verify"
        };

        debugLog("processMACOTPSubmit AuthSvcClient sending to verify_gateway_macotp: " + JSON.stringify(body));
        let authsvcResponseStr = AuthSvcClient.execute(JSON.stringify(body));
        debugLog("processMACOTPSubmit AuthSvcClient result: " + authsvcResponseStr);

        let authsvcResponse = JSON.parse(''+authsvcResponseStr);

        if (authsvcResponse.status == "success") {
            // success - may as well remove state
            stateObj = AuthSvcState.getAndRemoveState(stateId + "_StateObj");

            otpVerified = true;
            result = {"messageId":"CSIAH0620I","messageDescription":"The authentication attempt for the method [" + deliveryType + "] was successful."};
        } else if (authsvcResponse.status == "pause") {
            // probably an OTP entry error, need to retain updated stateId and return an error
            let jsonBody = authsvcResponse.response;
            stateObj["stateId"] = jsonBody.stateId;
            AuthSvcState.storeState(stateId + "_StateObj", stateObj);
        }
    }

    if (!otpVerified) {
        let error = {"messageId":"CSIAH0619E","messageDescription":"The authentication attempt for the method ["
            + deliveryType + "] failed."};
        throw error;
    }

    return result;
}

function getDeviceObjFromRegistration(scimID, username, reg, regid, fingerprintSupport) {
    // whilst the device.id attribute populated below is logically the authenticator id, for
    // the IVIA integration we set it to the logical fingerprintMethod id or userPresenceMethod id
    // so that when returned as part of mobile push kick-off we know precisely
    // which response policy (userpresence or fingerprint) to auto-select for invocation.
    // It allows mobilePushKickoff to select userpresence or fingerprint response
    // policy in the case where the same authenticator registration has both.

    //
    // also deviceType is used in the display to human about what method to select.
    // If IVIA has both biometric (e.g. fingerprint) and user-presence registered, there
    // is no way for the user to see the difference, so we annotate the deviceType
    //
    let result = {
        "id": regid,
        "owner": scimID,
        "enabled": reg.isEnabled(),
        "clientId": "AuthenticatorClient",
        "creationTime": "2019-01-01T00:00:00.000Z",
        "state": "ACTIVE",
        "attributes": {
            "applicationVersion": "unavaialble",
            "deviceType": IDMappingExtUtils.escapeHtml(emptyIfNull(reg.getDeviceType())) + (fingerprintSupport ? "-biometric" : "-userPresence"),
            "accountName": username,
            "platformType": "unavailable",
            "pushToken": "unavailable",
            "deviceName": "" + IDMappingExtUtils.escapeHtml(emptyIfNull(reg.getDeviceName())),
            "deviceId": "unavailable",
            "fingerprintSupport": fingerprintSupport,
            "verifySdkVersion": "unavailable",
            "osVersion": "" + IDMappingExtUtils.escapeHtml(emptyIfNull(reg.getOSVersion())),
            "frontCameraSupport": true,
            "faceSupport": false,
            "applicationId": "com.ibm.security.verifyapp"
        }
    };
    return result;
}

function processGetSignatures(ulh, currentClient, uri) {

    let result = {
      "total": 0,
      "limit": 200,
      "count": 200,
      "page": 1,
      "signatures": []
    };

    if (ENABLED_2FA_METHODS.mobilepush) {
        let regex = /^\/v1.0\/authnmethods\/signatures\?search=owner = "([^"]*)"&_embedded=true&sort=-signatures\/_embedded\/id$/;
        let m = unescape(uri).match(regex);
        if (m != null && m.length == 2) {
            let scimID = m[1];
            let username = ''+ScimClient.computeUsernameFromID(scimID);

            let user = ulh.getUser(username);

            if (user != null) {
                // perform authorizatin check - error thrown if this user is not allowed to be used from this client
                checkUserAuthorization(currentClient, user);

                // look up MMFA registrations for user using API available from 10.0.4.0
                let mmfaRegistrations = MechanismRegistrationHelper.getMmfaRegistrationsForUser(username);
                if (mmfaRegistrations != null && mmfaRegistrations.length > 0) {

                    // build state information about registrations - we decide what to do with them afterward
                    let fingerprintMethods = [];
                    let userPresenceMethods = [];

                    debugLog("mmfaRegistrations: " + mmfaRegistrations.length);
                    for (let i = 0; i < mmfaRegistrations.length; i++) {
                        let reg = mmfaRegistrations[i];
                        debugLog("["+i+"]: " + reg.toJson());

                        // only process if this registration is enabled
                        if (reg.isEnabled()) {
                            
                            if (reg.hasFingerprintEnrolled()) {
                                let regid = createUUID();
                                let deviceObj = getDeviceObjFromRegistration(scimID, username, reg, regid, true);
                                fingerprintMethods.push({
                                    "id":  regid,
                                    "owner": scimID,
                                    "enabled": true,
                                    "validated": true,
                                    "enrollmentUri": "undefined",
                                    "methodType": "signature",
                                    "creationTime": "2019-01-01T00:00:00.000Z",
                                    "subType": "fingerprint",
                                    "attributes": {
                                        "deviceSecurity": true,
                                        "authenticatorUri": "undefined",
                                        "authenticatorId": ''+reg.getAuthenticatorId(),
                                        "additionalData": [],
                                        "algorithm": "RSASHA256"
                                    },
                                    "_embedded": deviceObj
                                });
                            }

                            if (reg.hasUserPresenceEnrolled()) {
                                let regid = createUUID();
                                let deviceObj = getDeviceObjFromRegistration(scimID, username, reg, regid, false);
                                userPresenceMethods.push({
                                    "id":  regid,
                                    "owner": scimID,
                                    "enabled": true,
                                    "validated": true,
                                    "enrollmentUri": "undefined",
                                    "methodType": "signature",
                                    "creationTime": "2019-01-01T00:00:00.000Z",
                                    "subType": "userPresence",
                                    "attributes": {
                                        "deviceSecurity": false,
                                        "authenticatorUri": "undefined",
                                        "authenticatorId": ''+reg.getAuthenticatorId(),
                                        "additionalData": [],
                                        "algorithm": "RSASHA256"
                                    },
                                    "_embedded": deviceObj
                                });
                            }
                        } else {
                            debugLog("Not using registration because it is disabled.");
                        }
                    }

                    /*
                    * Now that we have performed enrollment discovery, decide what to return to the client
                    */

                    /*
                    * If fingerprint methods are enabled, and we have at least one, add to the results
                    */
                    if ((ENABLED_MOBILE_PUSH_METHODS.bestAvailable || ENABLED_MOBILE_PUSH_METHODS.fingerprint) && fingerprintMethods != null && fingerprintMethods.length > 0) {
                        debugLog("There are fingerprintMethods: " + fingerprintMethods.length);

                        for (let i = 0; i < fingerprintMethods.length; i++) {
                            result.signatures.push(fingerprintMethods[i]);
                            result.total = result.total + 1;

                            // also store method state object so that if used, kick-off process can retrieve it
                            let methodStateObj = {
                                "id": fingerprintMethods[i].id,
                                "username": username,
                                "scimID": scimID,
                                "authenticatorId": fingerprintMethods[i].attributes["authenticatorId"],
                                "fingerprint": true
                            };
                            AuthSvcState.storeState(fingerprintMethods[i].id, methodStateObj);
                        }
                    }

                    /*
                    * If user presence methods are explicitly enabled (or best available is enabled and we don't have any fingerprint methods) add any we have
                    */
                    if ((((!ENABLED_MOBILE_PUSH_METHODS.bestAvailable && ENABLED_MOBILE_PUSH_METHODS.userPresence) || (ENABLED_MOBILE_PUSH_METHODS.bestAvailable && result.total == 0)))
                            && userPresenceMethods != null && userPresenceMethods.length > 0) {
                        debugLog("There are userPresenceMethods: " + userPresenceMethods.length);
                        for (let i = 0; i < userPresenceMethods.length; i++) {
                            result.signatures.push(userPresenceMethods[i]);
                            result.total = result.total + 1;

                            // also store method state object so that if used, kick-off process can retrieve it
                            let methodStateObj = {
                                "id": userPresenceMethods[i].id,
                                "username": username,
                                "scimID": scimID,
                                "authenticatorId": userPresenceMethods[i].attributes["authenticatorId"],
                                "fingerprint": false
                            };
                            AuthSvcState.storeState(userPresenceMethods[i].id, methodStateObj);
                        }
                    }
                } else {
                    debugLog("No registered mobile multi-factor authenticators");
                }
            } else {
                debugLog("User not found: " + username);
            }
        } else {
            debugLog("Unable to extract owner information from signatures search URI");
        }
    } else {
        debugLog("Mobile push support not enabled, returning empty signatures list");
    }

    return result;

    // an example captured from CI - good for debug reference
    /*
    var result = {
              "total": 2,
              "limit": 200,
              "count": 200,
              "page": 1,
              "signatures": [
                {
                  "owner": "640004N89K",
                  "enrollmentUri": "https://REDACTED.ice.ibmcloud.com/v1.0/authnmethods/signatures/6a10bb02-a5ce-4b7a-8682-fa627c2261f2",
                  "methodType": "signature",
                  "creationTime": "2019-11-12T02:33:05.705Z",
                  "validated": true,
                  "_embedded": {
                    "owner": "640004N89K",
                    "clientId": "1f87a87a-25c7-4051-9c19-f2865e0c1f66",
                    "creationTime": "2019-11-12T02:32:54.054Z",
                    "attributes": {
                      "applicationVersion": "2.3.0 (6)",
                      "deviceType": "iPhone",
                      "accountName": "emily",
                      "platformType": "IOS",
                      "pushToken": "REDACTED",
                      "deviceName": "ShaneIPhone",
                      "deviceId": "E5725680-A318-4498-B181-29405BAC1F9E",
                      "fingerprintSupport": true,
                      "verifySdkVersion": "2.0.5 (1)",
                      "osVersion": "13.1.3",
                      "frontCameraSupport": true,
                      "faceSupport": false,
                      "applicationId": "com.ibm.security.verifyapp"
                    },
                    "id": "9cdb4e1d-94d1-40e6-8d56-956dcdc634ce",
                    "state": "ACTIVE",
                    "enabled": true
                  },
                  "subType": "fingerprint",
                  "attributes": {
                    "deviceSecurity": true,
                    "authenticatorUri": "https://REDACTED.ice.ibmcloud.com/v1.0/authenticators/9cdb4e1d-94d1-40e6-8d56-956dcdc634ce",
                    "authenticatorId": "9cdb4e1d-94d1-40e6-8d56-956dcdc634ce",
                    "additionalData": [],
                    "algorithm": "RSASHA256"
                  },
                  "id": "6a10bb02-a5ce-4b7a-8682-fa627c2261f2",
                  "enabled": true
                },
                {
                  "owner": "640004N89K",
                  "enrollmentUri": "https://REDACTED.ice.ibmcloud.com/v1.0/authnmethods/signatures/9215d557-129f-4712-afc9-288d286c79e1",
                  "methodType": "signature",
                  "creationTime": "2019-11-12T02:32:56.515Z",
                  "validated": true,
                  "_embedded": {
                    "owner": "640004N89K",
                    "clientId": "1f87a87a-25c7-4051-9c19-f2865e0c1f66",
                    "creationTime": "2019-11-12T02:32:54.054Z",
                    "attributes": {
                      "applicationVersion": "2.3.0 (6)",
                      "deviceType": "iPhone",
                      "accountName": "emily",
                      "platformType": "IOS",
                      "pushToken": "REDACTED",
                      "deviceName": "ShaneIPhone",
                      "deviceId": "E5725680-A318-4498-B181-29405BAC1F9E",
                      "fingerprintSupport": true,
                      "verifySdkVersion": "2.0.5 (1)",
                      "osVersion": "13.1.3",
                      "frontCameraSupport": true,
                      "faceSupport": false,
                      "applicationId": "com.ibm.security.verifyapp"
                    },
                    "id": "9cdb4e1d-94d1-40e6-8d56-956dcdc634ce",
                    "state": "ACTIVE",
                    "enabled": true
                  },
                  "subType": "userPresence",
                  "attributes": {
                    "deviceSecurity": false,
                    "authenticatorUri": "https://REDACTED.ice.ibmcloud.com/v1.0/authenticators/9cdb4e1d-94d1-40e6-8d56-956dcdc634ce",
                    "authenticatorId": "9cdb4e1d-94d1-40e6-8d56-956dcdc634ce",
                    "additionalData": [],
                    "algorithm": "RSASHA256"
                  },
                  "id": "9215d557-129f-4712-afc9-288d286c79e1",
                  "enabled": true
                }
              ]
            };
            */
}

function mobilePushKickoff(methodObj, contextMessage) {
    let result = {};

    // now time to kick it off with IVIA
    let body = {
        "PolicyId": "urn:ibm:security:authentication:asf:verify_gateway_mmfa_initiate",
        "username": methodObj.username,
        "contextMessage": contextMessage,
        "policyURI": (methodObj.fingerprint ? AUTHSVC_POLICYURI_RESPONSE_FINGERPRINT : AUTHSVC_POLICYURI_RESPONSE_USERPRESENCE),
        "operation": "verify"
    };

    debugLog("mobilePushKickoff AuthSvcClient sending to verify_gateway_mmfa_initiate: " + JSON.stringify(body));
    let authsvcResponseStr = AuthSvcClient.execute(JSON.stringify(body));
    debugLog("mobilePushKickoff AuthSvcClient result: " + authsvcResponseStr);

    let authsvcResponse = JSON.parse(''+authsvcResponseStr);

    if (authsvcResponse.status == "pause") {
        let jsonBody = authsvcResponse.response;

        // establish initial state object
        let stateObj = {
                "stateId": jsonBody["stateId"],
                "methodObj": methodObj,
                "policyURI": body.policyURI
        };

        // now hand off to next step, which is to select the device to use
        result = mobilePushSelectDevice(stateObj);
    } else {
        // response status not "pause"
        throwError("mobilePushKickoff", "Bad AuthSvcClient response status: " + authsvcResponse.status);
    }

    return result;
}

function mobilePushSelectDevice(stateObj) {
    let result = {};

    // return the authenticator id remembered as part of the methodObj as the mmfa.user.device.id
    let body = {
        "StateId": stateObj.stateId,
        "mmfa.user.device.id": stateObj.methodObj.authenticatorId,
        "policyURI": stateObj.policyURI,
        "operation": "verify"
    };

    debugLog("mobilePushSelectDevice AuthSvcClient sending to authsvc: " + JSON.stringify(body));
    let authsvcResponseStr = AuthSvcClient.execute(JSON.stringify(body));
    debugLog("mobilePushSelectDevice AuthSvcClient result: " + authsvcResponseStr);

    let authsvcResponse = JSON.parse(''+authsvcResponseStr);

    if (authsvcResponse.status == "pause") {
        let jsonBody = authsvcResponse.response;

        // {"mechanism":"urn:ibm:security:authentication:asf:mechanism:mmfa","stateId":"lkpe40Y5pRKoouQzDuzDHOuCXYUtuYk16XRhMZ61qabbG0SBKiuPA8el8sbhQfiIywy9EnN4jKCDXjDL0IYl17F5kb4pXpVz8jxTB06cFxTNx6NomYluGe82geA92GJw","location":"/mga/sps/apiauthsvc?StateId=lkpe40Y5pRKoouQzDuzDHOuCXYUtuYk16XRhMZ61qabbG0SBKiuPA8el8sbhQfiIywy9EnN4jKCDXjDL0IYl17F5kb4pXpVz8jxTB06cFxTNx6NomYluGe82geA92GJw","transactionId":"4d9ae6f7-b4a6-43df-a6ad-e466f2a0efaa","status":"pending"}

        // update stateObj with new stateId before we store against the transactionId as lookup key
        let transactionId = jsonBody["transactionId"];
        let newStateId = jsonBody["stateId"];
        let now = new Date();
        // 5 minutes
        let expiry = new Date(now.getTime() + PERSISTENT_CACHE_TIMEOUT * 1000);

        stateObj.stateId = newStateId;

        // now build CI-like response
        // This has to be a 202 Accepted, and ideally should include a Location header which matches the transactionUri from the example
        // response I captured below
        /*
        var exampleCIResponse = {
          "owner": "640004N89K",
          "userActions": [],
          "transactionUri": "https://REDACTED.ice.ibmcloud.com/v1.0/authenticators/9cdb4e1d-94d1-40e6-8d56-956dcdc634ce/verifications/972937f3-6d3f-4eb3-bd8f-f0db66ae34ba",
          "creationTime": "2019-11-20T03:38:23.041Z",
          "authenticationMethods": [
            {
              "methodType": "signature",
              "subType": "fingerprint",
              "id": "6a10bb02-a5ce-4b7a-8682-fa627c2261f2",
              "additionalData": []
            }
          ],
          "expiryTime": "2019-11-20T03:39:23.041Z",
          "transactionData": "{\"originIpAddress\":\"DESKTOP-JJ291EP\",\"originUserAgent\":\"IBM Radius Server\",\"additionalData\":[],\"message\":\"Do you approve the request from DESKTOP-JJ291EP?\",\"timestamp\":\"2019-11-20T03:38:23.041Z\"}",
          "authenticatorId": "9cdb4e1d-94d1-40e6-8d56-956dcdc634ce",
          "id": "972937f3-6d3f-4eb3-bd8f-f0db66ae34ba",
          "state": "PENDING",
          "logic": "AND",
          "pushNotification": {
            "sendState": "SENDING",
            "startTime": "2019-11-20T03:38:23.041Z",
            "message": "Do you approve the request from DESKTOP-JJ291EP?",
            "send": true,
            "pushToken": "hBtnztEWM8V0yOj1:WsJ1Fq4S"
          }
        };
        */

        // our constructed response
        result = {
          "httpStatusCode": "202",
          "owner": stateObj.methodObj.scimID,
          "userActions": [],
          "transactionUri": POINT_OF_CONTACT_URL + "/v1.0/authenticators/" + stateObj.methodObj.id + "/verifications/" + transactionId,
          "creationTime": now.toISOString(),
          "authenticationMethods": [
            {
              "methodType": "signature",
              "subType": (stateObj.methodObj.fingerprint ? "fingerprint" : "userPresence"),
              "id": stateObj.methodObj.id,
              "additionalData": []
            }
          ],
          "expiryTime": expiry.toISOString(),
          "transactionData": "{\"originIpAddress\":\"unavailable\",\"originUserAgent\":\"unavailable\",\"additionalData\":[],\"message\":\"unavailable\",\"timestamp\":\"unavailable\"}",
          "authenticatorId": stateObj.methodObj.id,
          "id": transactionId,
          "state": "PENDING",
          "logic": "AND",
          "pushNotification": {
            "sendState": "SENDING",
            "startTime": ((new Date()).toISOString()),
            "message": "unavailable",
            "send": true,
            "pushToken": "unavailable"
          }
        };

        stateObj.transaction = result;
        stateObj.testCount = 0;
        AuthSvcState.storeState(transactionId, stateObj);
    } else {
        // response status not "pause"
        throwError("mobilePushSelectDevice", "Bad AuthSvcClient response status: " + authsvcResponse.status);
    }

    return result;
}

function processSignatureVerificationKickoff(ulh, currentClient, uri, contextMessage) {
    let result = {};
    let regex = /^\/v1.0\/authenticators\/([^\/]*)\/verifications$/;
    let m = unescape(uri).match(regex);
    if (m != null && m.length == 2) {
        let methodId = m[1];
        debugLog("processSignatureVerificationKickoff: Working with methodId: " + methodId);

        let methodObj = AuthSvcState.getState(methodId);
        if (methodObj != null) {
            // kick off a mobile-push authentication
            result = mobilePushKickoff(methodObj, contextMessage);
        } else {
            throwError("processSignatureVerificationKickoff", "Unable to retrieve method state");
        }
    } else {
        throwError("processSignatureVerificationKickoff", "Unable to match methodId in uri");
    }

    return result;
}

function processPollSignatureVerification(ulh, currentClient, uri) {
    let result = {};

    let regex = /^\/v1.0\/authenticators\/[^\/]*\/verifications\/(.*)$/;
    let m = unescape(uri).match(regex);
    if (m != null && m.length == 2) {
        let transactionId = m[1];

        // retrieve the stateObj from the transactionId
        debugLog("processPollSignatureVerification looking up state for transactionId: " + transactionId);
        let stateObj = AuthSvcState.getState(transactionId);
        if (stateObj == null || stateObj.stateId == null) {
            let error = { "error": "Unable to retrieve authsvc session state" };
            throw error;
        }
        debugLog("stateObj: " + JSON.stringify(stateObj));

        // poll the authsvc to see if the transaction is complete
        let body = {
            "StateId": stateObj.stateId,
            "operation": "verify"
        };

        debugLog("processPollSignatureVerification AuthSvcClient sending to authsvc: " + JSON.stringify(body));
        let authsvcResponseStr = AuthSvcClient.execute(JSON.stringify(body));
        debugLog("processPollSignatureVerification AuthSvcClient result: " + authsvcResponseStr);

        let authsvcResponse = JSON.parse(''+authsvcResponseStr);

        if (authsvcResponse.status == "success") {

            // this is the success path for IVIA
            stateObj.transaction.state = "VERIFY_SUCCESS";

        } else if (authsvcResponse.status == "pause") {

            let jsonBody = authsvcResponse.response;
            // check result status (pending, etc) and update transaction as appropriate
            let txnStatus = jsonBody["status"];
            if (txnStatus == "pending") {
                // just refresh stateId in stateObj and re-store
                let newStateId = jsonBody["stateId"];
                stateObj.stateId = newStateId;
                AuthSvcState.storeState(transactionId, stateObj);
            } else {
                // unknown error
                stateObj.transaction.state = "VERIFY_FAILED";
            }
        } else if (authsvcResponse.status == "abort") {

            // this is the denied path for IVIA
            stateObj.transaction.state = "USER_DENIED";

        } else {
            // should be anything else
            let error = { "error": "Bad AuthSvcClient response status: " + authsvcResponse.status };
            throw error;
        }

        // send back potentially updated transaction
        result = stateObj.transaction;
        result["httpStatusCode"] = "200";
    } else {
        throwError("processPollSignatureVerification", "Unable to match methodId in uri");
    }

    return result;
}

function processSuccessResponse(r) {
    debugLog("infomap_verify_gateway_entry processSuccessResponse("+(r != null ? JSON.stringify(r) : "")+")");
    let  strResponseCode = r != null ? "200" : "204";
    // consume http status code override if supplied
    if (r != null && r.httpStatusCode != null) {
        strResponseCode = r.httpStatusCode;
        delete r.httpStatusCode;
    }

    // content-type
    let strContentType = "application/json";
    if (r != null && r.httpContentType != null) {
        strContentType = r.httpContentType;
        delete r.httpContentType;
    }

    // the message body
    let strResult = (r != null ? JSON.stringify(r) : "");

    sendResponse(strResponseCode, strContentType, strResult);
}


function processErrorResponse(e) {
    /* error handling - e should be JSON. Default response http status code to 400 unless overridden */
    let strResponseCode = "400";

    // consume http status code override if supplied
    if (e != null && e.httpStatusCode != null) {
        strResponseCode = e.httpStatusCode;
        delete e.httpStatusCode;
    }
    // content-type
    let strContentType = "application/json";
    if (e != null && e.httpContentType != null) {
        strContentType = e.httpContentType;
        delete e.httpContentType;
    }

    // error message body
    let strResult = (e != null ? JSON.stringify(e): "");

    sendResponse(strResponseCode, strContentType, strResult);
}

function sendResponse(statusCodeStr, contentTypeStr, strResult) {
    debugLog("infomap_verify_gateway_entry sendResponse @HTTP_RESPONSE_CODE@: " + statusCodeStr
        + " @HTTP_CONTENT_TYPE@: " + contentTypeStr + " @AUTHSVC_JSON_RESPONSE@: " + strResult);
    macros.put("@HTTP_RESPONSE_CODE@", statusCodeStr);
    macros.put("@HTTP_CONTENT_TYPE@", contentTypeStr);
    macros.put("@AUTHSVC_JSON_RESPONSE@", strResult);
    page.setValue("/authsvc/authenticator/verify_gateway/response.html");
}


//////////// MAIN BODY STARTS HERE

debugLog("infomap_verify_gateway_entry has been called");
dumpContext();

let result = {};

// read request URI - this will tell us which CI URL was being invoked
let uri = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "uri");
debugLog("infomap_verify_gateway_entry received uri: " + uri);

try {
    /*
     * Check that the infomap is being called by a trusted OAuth client. If it's not,
     * error out.
     */
    let currentClient = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "username");
    if (!(currentClient != null && allowedClients.indexOf(''+currentClient) >= 0)) {
        throwErrorWithCode("main", "Not authenticated as a trusted client", "401");
    }

    // prepare UserLookupHelper
    let ulh = new UserLookupHelper();
    // use Username Password mech config
    ulh.init(true);

    /* This search is done to resolve username to IUI */
    if (uri.indexOf('/v2.0/Users?filter=userName') == 0) {
        result = processUsersRequest(ulh, currentClient, ''+uri);

    /* This request is to perform user password authentication (used for example with the RADIUS gateway) */
    } else if (uri.indexOf('/v2.0/Users/authentication') == 0) {
        let userName = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "userName");
        let password = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "password");
        result = processUserAuthentication(ulh, currentClient, ''+uri, ''+userName, ''+password);

    /* This search seems to be done when using transient methods. Don't move the condition above the previous one because it's a superset match */
    } else if (uri.indexOf('/v2.0/Users/') == 0) {
        result = processUserLookup(ulh, currentClient, ''+uri);


    /* This search is done to discover available authentication factors - new for v2.0 factors API */
    } else if (uri.indexOf('/v2.0/factors?search=userId') == 0) {
        result = processFactorsLookup(ulh, currentClient, ''+uri);

    /* This request is to perform TOTP search (winpwd-and-totp) - new for v2.0 factors API */
    } else if (ENABLED_2FA_METHODS.totp && uri.indexOf('/v2.0/factors/totp?search=userId') == 0) {
        result = processFactorsTOTPLookup(ulh, currentClient, ''+uri);

    /* This request is to perform TOTP verification - new for v2.0 factors API */
    } else if (ENABLED_2FA_METHODS.totp && uri.indexOf('/v2.0/factors/totp/') == 0) {
        let totp = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "otp");
        result = processFactorsTOTPVerification(ulh, currentClient, ''+uri, ''+totp);

    /* This request is to kick-off transient email address OTP - new for v2.0 factors API */
    } else if (ENABLED_2FA_METHODS.emailotp && uri.equals('/v2.0/factors/emailotp/transient/verifications')) {
        let emailAddress = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "emailAddress");
        result = processFactorsMACOTPStart(ulh, currentClient, ''+uri, 'emailotp', ''+emailAddress);

    /* This request is to kick-off transient email address OTP - new for v2.0 factors API */
    } else if (ENABLED_2FA_METHODS.emailotp && uri.indexOf('/v2.0/factors/emailotp/transient/verifications/') == 0) {
        let otp = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "otp");
        result = processFactorsMACOTPSubmit(ulh, currentClient, ''+uri, 'emailotp', ''+otp);

    /* This request is to kick-off transient sms OTP - new for v2.0 factors API */
    } else if (ENABLED_2FA_METHODS.smsotp && uri.equals('/v2.0/factors/smsotp/transient/verifications')) {
        let phoneNumber = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "phoneNumber");
        result = processFactorsMACOTPStart(ulh, currentClient, ''+uri, 'smsotp', ''+phoneNumber);

    /* This request is to kick-off transient email address OTP - new for v2.0 factors API */
    } else if (ENABLED_2FA_METHODS.smsotp && uri.indexOf('/v2.0/factors/smsotp/transient/verifications/') == 0) {
        let otp = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "otp");
        result = processFactorsMACOTPSubmit(ulh, currentClient, ''+uri, 'smsotp', ''+otp);


    /* This search is done to discover if TOTP is enabled (winpwd-then-choice-then-otp) - DEPRECATED */
    } else if (uri.indexOf('/v1.0/authnmethods?search=owner') == 0) {
        result = processAuthenticationMethodsSearch(ulh, currentClient, ''+uri);

    /* This search is also used to discover if TOTP is enabled (winpwd-and-totp) - DEPRECATED */
    } else if (uri.indexOf('/v1.0/authnmethods/totp?search=owner') == 0) {
        result = processAuthenticationMethodsTOTPSearch(ulh, currentClient, ''+uri);

    /* This request is to perform TOTP verification - DEPRECATED */
    } else if (ENABLED_2FA_METHODS.totp && uri.indexOf('/v1.0/authnmethods/totp/') == 0) {
        let totp = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "totp");
        result = processTOTPVerification(ulh, currentClient, ''+uri, ''+totp);

    /* This request supports emailotp kick-off - DEPRECATED */
    } else if (ENABLED_2FA_METHODS.emailotp && uri.equals('/v1.0/authnmethods/emailotp/transient/verification')) {
        let emailAddress = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "otpDeliveryEmailAddress");
        result = processMACOTPStart(ulh, currentClient, ''+uri, 'emailotp', ''+emailAddress);

    /* This request supports emailotp verification - DEPRECATED */
    } else if (ENABLED_2FA_METHODS.emailotp && uri.indexOf('/v1.0/authnmethods/emailotp/transient/verification/') == 0) {
        let otp = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "otp");
        result = processMACOTPSubmit(ulh, currentClient, ''+uri, 'emailotp', ''+otp);

    /* This request supports smsotp kick-off - DEPRECATED */
    } else if (ENABLED_2FA_METHODS.smsotp && uri.equals('/v1.0/authnmethods/smsotp/transient/verification')) {
        let mobileNumber = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "otpDeliveryMobileNumber");
        result = processMACOTPStart(ulh, currentClient, ''+uri, 'smsotp', ''+mobileNumber);

    /* This request supports smsotp verification - DEPRECATED */
    } else if (ENABLED_2FA_METHODS.smsotp && uri.indexOf('/v1.0/authnmethods/smsotp/transient/verification/') == 0) {
        let otp = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "otp");
        result = processMACOTPSubmit(ulh, currentClient, ''+uri, 'smsotp', ''+otp);

    /* This request is for discovery of mobile push methods */
    } else if (uri.indexOf('/v1.0/authnmethods/signatures?search=owner') == 0) {
        result = processGetSignatures(ulh, currentClient, ''+uri);

    /* This request is for polling to see if mobile push is complete. Do not move it below the next condition */
    } else if (ENABLED_2FA_METHODS.mobilepush && uri.matches('/v1.0/authenticators/[^/]*/verifications/.*')) {
        result = processPollSignatureVerification(ulh, currentClient, ''+uri);

    /* This request is for mobile push kick-off. Don't move the condition above the previous one because it's a superset match */
    } else if (ENABLED_2FA_METHODS.mobilepush && uri.indexOf('/v1.0/authenticators/') == 0) {
        let pushNotification = JSON.parse(''+context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "pushNotification"));
        result = processSignatureVerificationKickoff(ulh, currentClient, ''+uri, pushNotification.message);
    } else {
        debugLog("infomap_verify_gateway_entry unexpected URI: " + uri);
        throwError("main", "Invalid URI");
    }

    processSuccessResponse(result);

} catch (e) {
    processErrorResponse(e);
}

//this InfoMap actually never logs in
success.setValue(false);

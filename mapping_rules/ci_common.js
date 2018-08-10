importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

function checkLogin() {
    var sessionUsername = getUsernameFromSession();
    var username = getUsername();

    // If we have the username from the WebSEAL session, return immediately.
    if(sessionUsername != null) {
        return sessionUsername;
    }

    // If we have no username from either session, state, or parameter, return 
    // a login page.
    if(username == null) {
        page.setValue("/authsvc/authenticator/ci/login.html");
        macros.put("@ERROR_MESSAGE@", errorMessages["user_not_found"]);
        return null;
    }

    // We've been given the username. Check if username/password auth has already
    // been done successfully for this session by fetching basicAuth from the
    // state map.
    var basicAuth = state.get("basicAuth");
    var password = getPassword();

    if(basicAuth != null && basicAuth == username) {
        return username;
    } else if(password != null) {
        // If we were given the password as well, attempt auth.
        var justAuthed = CiClient.basicAuthentication(conn, username, password, getLocale());
        if(justAuthed) {
            // If successful, save the just authed username as "basicAuth" in
            // the state map.
            state.put("basicAuth", username);
            return username;
        } else {
            // The login request failed. Return an error page via our handleError
            // method.
            handleError(errorMessages["login_failed"], null);
            return null;
        }
    } else if(username != null) {
        // We have a username but no password. Return a login page.
        macros.put("@USERNAME@", username);
        page.setValue("/authsvc/authenticator/ci/login.html");
        return null;
    }
}

function getUserId(conn, username) {
    var userId = state.get("userId");
    if(userId == null) {
        var user = CiClient.getUser(conn, username, getLocale());
        if (user != null) {
            // We've successfully gotten the user ID. Save it and the username
            // in the state map.
            var userObj = JSON.parse(user);
            userId = userObj.id;
            state.put("userId", userId);
            state.put("username", username);

            // Also fetch some details to display on the USC page.
            var emails = userObj.emails;
            if(emails != null && emails.length > 0) {
                state.put("email", emails[0].value);
                macros.put("@EMAIL@", emails[0].value);
            }
            // We have two options here for a nice display name for the
            // user. We could use the givenName, or the formatted name. The
            // formatted name can be manually modified by the CI
            // administrator to be correct per the user's culture, but
            // defaults to givenName lastName if not provided. So we will
            // use givenName by default. To use the formatted name instead,
            // change name.givenName to name.formatted
            if(userObj.name != null && userObj.name.givenName != null) {
                state.put("name", userObj.name.givenName);
                macros.put("@NAME@", userObj.name.givenName);
            }
        } else {
            // The request failed. Return an error page via our handleError
            // method.
            handleError(errorMessages["user_not_found"], null);
        }
    } else {
        // If we already have the user ID, we should already have the email
        // and name saved. Fetch them to display on the USC page.
        var email = state.get("email");
        var name = state.get("name");
        if(email != null) {
            macros.put("@EMAIL@", email);
        }
        if(name != null) {
            macros.put("@NAME@", name);
        }
    }
    return userId;
}

/**
 * Check the given response for an error message. Overwrite errMessage if it's
 * included.
 */
function handleError(errMessage, resp) {
    var errorMessage = errMessage;

    if(resp != null) {
        IDMappingExtUtils.traceString("Error response: "+resp.getCode());
        IDMappingExtUtils.traceString("Error response body: "+resp.getBody());
        var json = getJSON(resp);

        if(json != null && json.messageDescription != null) {
            errorMessage = json.messageDescription;
        }
    }

    macros.put("@ERROR_MESSAGE@", errorMessage);
    page.setValue("/authsvc/authenticator/ci/error.html");
}

/**
 * Get the type from the state or from the request.
 */
function getType() {
    var type = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "type");
    if(type == null) {
        type = state.get("type");
    }
    return jsString(type);
}

/**
 * Get the OTP delivery detail from the session or from the request.
 */
function getOTPDelivery() {
    var otpDelivery = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "otpDelivery");
    if(otpDelivery == null) {
        otpDelivery = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "otpDelivery");
    }
    return jsString(otpDelivery);
}

/**
 * Get the mobile number from the state or from the given user object.
 */
function getMobileNumber(user) {
    var otpDelivery = state.get("mobileNumber");
    if(otpDelivery == null) {
        if(user != null) {
            if(user.phoneNumbers != null && user.phoneNumbers.length > 0) {
                for(var i = 0; i < user.phoneNumbers.length; i++) {
                    if(user.phoneNumbers[i].type == "mobile") {
                        otpDelivery = user.phoneNumbers[i].value;
                        state.put("mobileNumber", otpDelivery);
                        break;
                    }
                }
            }
        }
    }
    return jsString(otpDelivery);
}

/**
 * Get the email address from the state or from the given user object.
 */
function getEmailAddress(user) {
    var otpDelivery = state.get("emailAddress");
    if(otpDelivery == null) {
        if(user != null) {
            if(user.emails != null && user.emails.length > 0) {
                otpDelivery = user.emails[0].value;
                state.put("emailAddress", otpDelivery);
            }
        }
    }
    return jsString(otpDelivery);
}

/**
 * Get the mobile number from the session or from the request.
 */
function getMobileNumberFromCredential() {
    var otpDelivery = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "mobileNumber");
    if(otpDelivery == null) {
        otpDelivery = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "mobileNumber");
    }
    return jsString(otpDelivery);
}

/**
 * Get the email from the session or from the request.
 */
function getEmailAddressFromCredential() {
    var otpDelivery = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "emailAddress");
    if(otpDelivery == null) {
        otpDelivery = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "emailAddress");
    }
    return jsString(otpDelivery);
}

/**
 * Get the ID from the state or from the request.
 */
function getId() {
    var id = state.get("id");
    if(id == null) {
        id = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "id");
    }
    return jsString(id);
}

/**
 * Get the authenticator ID from the state or from the request.
 */
function getAuthenticatorId() {
    var authenticatorId = state.get("authenticatorId");
    if(authenticatorId == null) {
        authenticatorId = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "authenticatorId");
    }
    return jsString(authenticatorId);
}

/**
 * Get the verification ID from the state or from the request.
 */
function getVerificationId() {
    var verificationId = state.get("verificationId");
    if(verificationId == null) {
        verificationId = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "verificationId");
    }
    return jsString(verificationId);
}

/**
 * Get the validation ID from the state or from the request.
 */
function getValidationId() {
    var validationId = state.get("validationId");
    if(validationId == null) {
        validationId = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "validationId");
    }
    return jsString(validationId);
}

/**
 * Get the OTP from the state or from the request.
 */
function getOTP() {
    var otp = state.get("otp");
    if(otp == null) {
        otp = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "otp");
    }
    return jsString(otp);
}

/**
 * Get the action from the state or from the request.
 */
function getAction() {
    var action = state.get("action");
    if(action == null) {
        action = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "action");
    }
    return jsString(action);
}

/**
 * Get the username from the session
 */
function getUsernameFromSession() {
    var username = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username");
    return jsString(username);
}

/**
 * Get the username from the state, session, or request.
 */
function getUsername() {
    var username = state.get("username");
    if(username == null) {
        username = getUsernameFromSession();
    }
    if(username == null) {
        username = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "username");
    }
    return jsString(username);
}

/**
 * Get the password from the request.
 */
function getPassword() {
    var password = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "password");
    return jsString(password);
}

/**
 * Set the username into the session..
 */
function setUsername(username) {
    context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", username);
}

/**
 * Get the last validation from the state or from the request.
 */
function getLastValidation() {
    var lastValidation = state.get("lastValidation");
    if(lastValidation == null) {
        lastValidation = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "lastValidation");
    }
    return jsString(lastValidation);
}

/**
 * Get the enabled variable from the request.
 */
function getEnabled() {
    var enabled = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "enabled");
    return jsString(enabled);
}

/**
 * Get the auth status from the session.
 */
function getAuthStatus() {
    var status = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "authStatus");
    return jsString(status);
}

/**
 * Set the auth status into the session.
 */
function setAuthStatus(status) {
    context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "authStatus", status);
}

/**
 * Get the locale from the request.
 */
function getLocale() {
    var locale = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:header", "Accept-Language");
    return jsString(locale);
}

/**
 * Clean the state! At this point we remove the type, ID, verification ID, last
 * validation, and correlation.
 */
function cleanState() {
    state.remove("type");
    state.remove("id");
    state.remove("verificationId");
    state.remove("lastValidation");
    state.remove("correlation");
}

/**
 * Map the transient type to the basic type name.
 */
function mapTransientType(type) {
    var simpleType = "emailotp";
    if(type == "transientsms") {
        simpleType = "smsotp";
    }
    return simpleType;
}

/**
 * Attempt to parse the response for the JSON body.
 */
function getJSON(resp) {
    var json = null;
    if(resp != null && resp.getBody() != null) {
        try {
            json = JSON.parse(resp.getBody());
        } catch(e) {
            IDMappingExtUtils.traceString("Error response: "+e);
        }
    }
    return json;
}

/**
 * Get the values in the given object as an array.
 */
function objectValues(object) {
    var array = [];
    for (var i in object) {
        if (object.hasOwnProperty(i)) {
            array.push(object[i]);
        }
    }
    return array;
}

/**
 * Convert the given java string into a javascript string!
 */
function jsString(javaString) {
    if(javaString != null) {
        javaString = "" + javaString;
    }
    return javaString;
}

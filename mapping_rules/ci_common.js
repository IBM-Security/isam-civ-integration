importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

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
        username = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username");
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

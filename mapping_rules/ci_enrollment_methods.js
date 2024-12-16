importPackage(Packages.com.ibm.security.access.ciclient);
importPackage(Packages.com.ibm.security.access.server_connections);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("CI_Common");

// Copyright contributors to the IBM Verify Identity Access and Verify SaaS Strong Authentication Integration project.

// This variable controls the priority of Verify methods, for display and for initial try
// it out scenarios.
var verifyMethodPriority = ["face", "fingerprint", "userPresence"];

// Whether important events are audited
var auditEvents = false;

// The possible error messages returned by this rule.
var errorMessages = {
    "invalid_action"            : macros.get("@INVALID_ACTION@"), // "The action provided was invalid for this mechanism."
    "user_not_found"            : macros.get("@USER_NOT_FOUND_MSG@"), // "User not found."
    "login_failed"              : macros.get("@LOGIN_FAILED@"), // "Login failed. You have used an invalid user name or password."
    "auth_method_get_failed"    : macros.get("@AUTH_METHOD_GET_FAIL_MSG@"), // "Retrieving authentication methods failed."
    "registration_failed"       : macros.get("@REGISTRATION_FAILED_MSG@"), // "Registration failed."
    "registration_failed_colon" : macros.get("@REGISTRATION_FAILED_COLON_MSG@"), // "Registration failed:"
    "validation_failed"         : macros.get("@VALIDATION_FAILED_MSG@"), // "Validation failed."
    "validation_failed_colon"   : macros.get("@VALIDATION_FAILED_COLON_MSG@"), // "Validation failed:"
    "verification_failed"       : macros.get("@VERIFICATION_FAILED_MSG@"), // "Verification failed."
    "verification_failed_colon" : macros.get("@VERIFICATION_FAILED_COLON_MSG@"), // "Verification failed:"
    "update_failed"             : macros.get("@UPDATE_FAILED_MSG@"), // "Update failed."
    "update_failed_colon"       : macros.get("@UPDATE_FAILED_COLON_MSG@"), // "Update failed:"
    "removal_failed"            : macros.get("@REMOVAL_FAILED_MSG@"), // "Removal failed."
    "removal_failed_colon"      : macros.get("@REMOVAL_FAILED_COLON_MSG@"), // "Removal failed:"
    "no_type"                   : macros.get("@NO_TYPE_MSG@"), // "No type provided."
    "no_id"                     : macros.get("@NO_ID_MSG@"), // "No ID provided."
    "no_otp"                    : macros.get("@NO_OTP_MSG@"), // "No OTP provided."
    "no_otp_delivery"           : macros.get("@NO_OTP_DELIVERY_MSG@"), // "No OTP delivery detail provided."
    "no_validation_id"          : macros.get("@NO_VALIDATION_ID_MSG@"), // "No validation ID provided."
    "no_verification_id"        : macros.get("@NO_VERIFICATION_ID_MSG@"), // "No verification ID provided."
    "create_transaction_failed" : macros.get("@CREATE_TRANSACTION_FAILED_MSG@"), // "Could not create transacton."
    "create_validation_failed"  : macros.get("@CREATE_VALIDATION_FAILED_MSG@"), // "Could not create validation."
    "create_verification_failed": macros.get("@CREATE_VERIFICATION_FAILED_MSG@") // "Could not create verification."
}

/**
 * Get the email address from the state or from the given user object.
 */
function enrollVerify(conn, userId, username) {

    // Check now to make sure we've saved a list of existing authenticators.
    var authenticators = JSON.parse(state.get("authenticators"));
    if(authenticators == null || authenticators.length == 0) {
        var resp = CiClientV2.getAuthenticators(conn, userId, getLocale());
        var authenticatorsJson = getJSON(resp);
        if (resp != null && resp.getCode() == 200 && authenticatorsJson != null) {
            authenticators = authenticatorsJson.authenticators;
        }
        state.put("authenticators", JSON.stringify(authenticators));
    }

    // The registration payload is the owner and the Verify
    // client ID (configured on the mechanism).
    var registrationJson = {"owner": userId, "clientId": jsString(macros.get("@VERIFY_CLIENT@")), "accountName": username};

    var resp = CiClientV2.registerAuthenticator(conn, JSON.stringify(registrationJson), true, getLocale());
    var json = getJSON(resp);
    if (resp != null && resp.getCode() == 200 && json != null) {

        // Verify registration returns as a QR code. Return it
        // to the end user for them to scan.
        macros.put("@QRCODE@", json.qrcode);
        macros.put("@ACCOUNT_NAME@", json.accountName);
        page.setValue("/authsvc/authenticator/ci/verify_registration.html");
        // Clean the state. cleanState is defined in CI_Common.js
        // Check the function definition to confirm which state variables
        // are cleared.
        cleanState();

        if(auditEvents) {
            // Also log an audit event for the successful register.
            IDMappingExtUtils.logCISelfCareAuditEvent(username, "registerVerify", macros.get("@SERVER_CONNECTION@"), "CI_Self_Care_Rule", "");
        }
    } else {
        // The request failed. Log an audit event for it.
        var code = resp != null ? "" + resp.getCode() : "Verify Registration failed";
        if(auditEvents) {
            IDMappingExtUtils.logCISelfCareAuditEvent(username, "registerVerify", macros.get("@SERVER_CONNECTION@"), "CI_Self_Care_Rule", code);
        }
        // Return an error page via our handleError method
        // (defined in CI_Common.js).
        handleError(errorMessages["registration_failed"], resp);
        // Clean the state. cleanState is defined in CI_Common.js
        // Check the function definition to confirm which state variables
        // are cleared.
        cleanState();
    }

    // Check now to make sure we've saved whether TOTP has already been registered.
    var authMethods = JSON.parse(state.get("authMethods"));
    if(authMethods == null || authMethods.length == 0) {
        var authMethodResp = CiClientV2.getFactors(conn, "userId=\"" + userId + "\"&type!=\"signature\"", getLocale());
        var authMethodJson = getJSON(authMethodResp);
        if (authMethodResp != null && authMethodResp.getCode() == 200 && authMethodJson != null) {
            state.put("authMethods", JSON.stringify(authMethodJson.factors));
        }
    }
}

function enrollEmailOrSMS(conn, type, userId, username) {

    // If the type is email or SMS OTP, the user had to include
    // an OTP delivery method in the request.
    var otpDelivery = getOTPDelivery();
    if(otpDelivery != null) {
        var enrollmentJson = {"userId": userId, "enabled": true};
        if(type == "smsotp") {
            enrollmentJson["phoneNumber"] = otpDelivery;
        } else {
            enrollmentJson["emailAddress"] = otpDelivery;
        }
        var resp = CiClientV2.enrollFactor(conn, type, JSON.stringify(enrollmentJson), false, getLocale());
        var json = getJSON(resp);
        if (resp != null && (resp.getCode() == 201 || resp.getCode() == 202) && json != null) {
            // Save the enrollment details to send back to the
            // USC page.
            macros.put("@ID@", json.id);
            state.put("id", json.id);
            macros.put("@VERIFICATION_ID@", "");
            macros.put("@TYPE@", type);
            macros.put("@CORRELATION@", "");
            page.setValue("/authsvc/authenticator/ci/enrollment.html");

            // Always perform a verification after enrollment.
            var verificationReq = {"correlation": jsString(Math.floor(1000 + Math.random() * 9000))};
            var verificationResp = CiClientV2.createFactorVerification(conn, type, json.id, JSON.stringify(verificationReq), getLocale());
            var verificationJson = getJSON(verificationResp);

            if (verificationResp != null && verificationResp.getCode() == 201 && verificationJson != null) {
                macros.put("@CORRELATION@", verificationJson.correlation);
                state.put("correlation", verificationJson.correlation);
                macros.put("@VERIFICATION_ID@", verificationJson.id);
                state.put("verificationId", verificationJson.id);
                macros.put("@REQUIRE_VALIDATION@", jsString(true));
            }
            macros.put("@IS_ENABLED@", jsString(json.enabled));
            macros.put("@CREATION_TIME@", json.created);

            if(auditEvents) {
                // Also log an audit event for the successful register.
                IDMappingExtUtils.logCISelfCareAuditEvent(username, "register" + type, macros.get("@SERVER_CONNECTION@"), "CI_Self_Care_Rule", "");
            }

            // If we have authMethods in the state, update it now.
            var authMethods = JSON.parse(state.get("authMethods"));
            if(authMethods != null && authMethods.length != 0) {
                authMethods.push(json);
                state.put("authMethods", JSON.stringify(authMethods));
            }

        } else {
            // The request failed. Log an audit event for it.
            var code = resp != null ? "" + resp.getCode() : type + " registration failed";
            if(auditEvents) {
                IDMappingExtUtils.logCISelfCareAuditEvent(username, "register" + type, macros.get("@SERVER_CONNECTION@"), "CI_Self_Care_Rule", code);
            }
            // Return an error page via our handleError method
            // (defined in CI_Common.js).
            handleError(errorMessages["registration_failed"], resp);
            // Clean the state. cleanState is defined in CI_Common.js
            // Check the function definition to confirm which state variables
            // are cleared.
            cleanState();
        }
    } else {
        // No email or phone number was supplied. Return an error
        // page via our handleError method (defined in CI_Common.js).
        handleError(errorMessages["registration_failed_colon"] + " " + errorMessages["no_otp_delivery"], resp);
    }
}

function enrollTOTP(conn, userId, username) {
    // TOTP enrollment is similar to Verify, in that a QR code
    // has to be scanned by the user.

    // The payload has owner, enabled, and the owner display name.
    var enrollmentJson = {"userId": userId, "enabled": true, "accountName": username};
    var resp = CiClientV2.enrollFactor(conn, "totp", JSON.stringify(enrollmentJson), "qrCodeInResponse=true", getLocale());
    var json = getJSON(resp);
    if (resp != null && resp.getCode() == 201 && json != null) {
        // We got the enrollment QR code. Return it to the end
        // user for them to scan.

        macros.put("@QRCODE@", json.attributes.qrCode);
        macros.put("@ID@", json.id);
        macros.put("@IS_VALIDATED@", jsString(json.validated));
        macros.put("@IS_ENABLED@", jsString(json.enabled));
        macros.put("@CREATION_TIME@", json.created);
        macros.put("@PERIOD@", jsString(json.attributes.period));
        macros.put("@DIGITS@", jsString(json.attributes.digits));
        macros.put("@SECRET@", json.attributes.secret);
        macros.put("@ALGORITHM@", json.attributes.algorithm);
        state.put("id", json.id);
        page.setValue("/authsvc/authenticator/ci/totp_enrollment.html");

        if(auditEvents) {
            // Also log an audit event for the successful register.
            IDMappingExtUtils.logCISelfCareAuditEvent(username, "registertotp", macros.get("@SERVER_CONNECTION@"), "CI_Self_Care_Rule", "");
        }

        // If we have authMethods in the state, update it now.
        var authMethods = JSON.parse(state.get("authMethods"));
        if(authMethods != null && authMethods.length != 0) {
            authMethods.push(json);
            state.put("authMethods", JSON.stringify(authMethods));
        }
    } else {
        // The request failed. Log an audit event for it.
        var code = resp != null ? "" + resp.getCode() : "totp registration failed";
        if(auditEvents) {
            IDMappingExtUtils.logCISelfCareAuditEvent(username, "registertotp", macros.get("@SERVER_CONNECTION@"), "CI_Self_Care_Rule", code);
        }
        // Return an error page via our handleError method
        // (defined in CI_Common.js).
        handleError(errorMessages["registration_failed"], resp);
        // Clean the state. cleanState is defined in CI_Common.js
        // Check the function definition to confirm which state variables
        // are cleared.
        cleanState();
    }
}

function validateOTP(conn) {
    // Validate the given OTP! This is only valid for TOTP, email,
    // and SMS OTPs.
    // The request has to include the type, ID, validation ID, and OTP.
    var type = getType();
    var id = getId();
    var verificationId = getVerificationId();
    var otp = getOTP();

    if(otp != null) {
        if(type == "smsotp" || type == "emailotp") {
            if(id != null && verificationId != null) {
                // Check method ownership.
                var authMethod = getAuthMethodById(id);
                if(authMethod != null && authMethod.userId == userId) {
                    var validationJson = {"otp":otp};

                    var resp = CiClientV2.verifyFactor(conn, type, id, verificationId, JSON.stringify(validationJson), getLocale());
                    if (resp != null && resp.getCode() == 204) {
                        // Return a status payload with success.
                        state.put("status", "success");
                        macros.put("@STATUS@", "success");
                        page.setValue("/authsvc/authenticator/ci/status.html");

                        // Clean the state. cleanState is defined in CI_Common.js
                        // Check the function definition to confirm which state variables
                        // are cleared.
                        cleanState();
                    } else {
                        // The request failed. Return an error page via our handleError
                        // method (defined in CI_Common.js).
                        handleError(errorMessages["validation_failed"], resp);
                    }
                } else {
                    // Authenticated user does not match auth method owner.
                    // Return an error page.
                    handleError(errorMessages["validation_failed"], null);
                }
            } else {
                // No ID or validation ID was supplied. Return an error
                // page via our handleError method (defined in CI_Common.js).
                if(id == null) handleError(errorMessages["validation_failed_colon"] + " " + errorMessages["no_id"], null);
                else if(verificationId == null) handleError(errorMessages["validation_failed_colon"] + " " + errorMessages["no_validation_id"], null);
            }
        } else if(type == "totp") {
            if(id != null) {
                var validationJson = {"otp":otp};

                // Check method ownership.
                var authMethod = getAuthMethodById(id);
                if(authMethod != null && authMethod.userId == userId) {

                    var resp = CiClientV2.verifyTOTPFactor(conn, id, JSON.stringify(validationJson), getLocale());
                    if (resp != null && resp.getCode() == 204) {
                        // Return a status payload with success.
                        state.put("status", "success");
                        macros.put("@STATUS@", "success");
                        page.setValue("/authsvc/authenticator/ci/status.html");
                        // Clean the state. cleanState is defined in CI_Common.js
                        // Check the function definition to confirm which state variables
                        // are cleared.
                        cleanState();
                    } else {
                        // The request failed. Return an error page via our handleError
                        // method (defined in CI_Common.js).
                        handleError(errorMessages["validation_failed"], resp);
                    }
                } else {
                    // Authenticated user does not match auth method owner.
                    // Return an error page.
                    handleError(errorMessages["validation_failed"], null);
                }
            } else {
                // No ID was supplied. Return an error page via our
                // handleError method (defined in CI_Common.js).
                handleError(errorMessages["validation_failed_colon"] + " " + errorMessages["no_id"], null);
            }
        } else {
            // No type was supplied. Return an error page via our
            // handleError method (defined in CI_Common.js).
            handleError(errorMessages["validation_failed_colon"] + " " + errorMessages["no_type"], null);
        }
    } else {
        // No OTP was supplied. Return an error page via our
        // handleError method (defined in CI_Common.js).
        handleError(errorMessages["validation_failed_colon"] + " " + errorMessages["no_otp"], null);
    }
}

function pollEnrollment(conn, userId) {
    var authenticators = JSON.parse(state.get("authenticators"));
    var authMethods = JSON.parse(state.get("authMethods"));

    var status = "unknown";
    var authenticatorId = getAuthenticatorId();

    if(authenticatorId != null) {
        // Just fetch our (hopefully) known ID.
        var resp = CiClientV2.getAuthenticator(conn, authenticatorId, getLocale());
        var json = getJSON(resp);
        if (resp != null && resp.getCode() == 200 && json != null && json.owner == userId) {
            if(json.state == "PENDING" || json.state == "ENROLLING") {
                status = "pending";
            } else if(json.state == "ACTIVE") {
                status = "success";
            }
        }
    } else {
        // Fall back to checking list
        var resp = CiClientV2.getAuthenticators(conn, userId, getLocale());
        var json = getJSON(resp);
        if (resp != null && resp.getCode() == 200 && json != null) {

            if(json.total > authenticators.length) {
                for(i = 0; i < json.total; i++) {
                    var authenticator = json.authenticators[i];
                    if(authenticator.state == "PENDING" || authenticator.state == "ENROLLING") {
                        // Assume this is our new authenticator
                        state.put("authenticatorId", authenticator.id);
                        status = "pending";
                        state.put("deviceName", authenticator.attributes.deviceName);
                    }
                }

                // If the length is longer, and none are pending, assume our new
                // one was added successfully.
                if(status == "unknown") {
                    status = "success";
                }
            } else {
                // QR Code probably hasn't been scanned yet.
                status = "pending";
            }
        }
    }

    if(status == "success") {
        // Check if TOTP was also added.
        var authMethodResp = CiClientV2.getFactors(conn, "userId=\"" + userId + "\"", getLocale());
        var authMethodJson = getJSON(authMethodResp);
        if (authMethodResp != null && authMethodResp.getCode() == 200 && authMethodJson != null) {

            if(authMethodJson.factors.length > authMethods.length) {
                for(i = 0; i < authMethodJson.factors.length; i++) {
                    if(authMethodJson.factors[i].type == "totp") {
                        if(!JSON.stringify(authMethods).includes("totp")) {
                            status = "successWithTOTP";
                            state.put("id", authMethodJson.factors[i].id);
                        }
                        break;
                    }
                }

                // We have more authMethods than before. Update the state with the new list.

                var authMethods = authMethodJson.factors.filter(method => {return method.type !== "signature" && method.type !== "signatures";});
                var signatureMethods = authMethodJson.factors.filter(method => {return method.type === "signature" || method.type === "signatures";});
                state.put("authMethods", JSON.stringify(authMethods));
                state.put("signatureMethods", JSON.stringify(signatureMethods));
            }
        }
    }
    if(status == "success" && authenticatorId != null) {
        // If status is still success, we didn't enroll in TOTP and we want to instead do
        // a push flow. Try and find a signature method for this enrollment.

        var signatureMethods = state.get("signatureMethods") ? JSON.parse(state.get("signatureMethods")) : [];

        if(signatureMethods.length > 0) {
            var highestPriority = null;
            var highestPriorityMethodId = null;
            for(i = 0; i < signatureMethods.length; i++) {
                var method = signatureMethods[i];
                var priority = verifyMethodPriority.indexOf(method.subType);
                if(priority != -1) {
                    if(highestPriority != null) {
                        if(priority < highestPriority) {
                            highestPriority = priority;
                            highestPriorityMethodId = method.id;
                        }
                    } else {
                        highestPriority = priority;
                        highestPriorityMethodId = method.id;
                    }
                }
            }
            if(highestPriorityMethodId != null) {
                state.put("id", highestPriorityMethodId);
                setIsVerifyEnrolling("true");
            }
        }
    }

    macros.put("@STATUS@", status);
    page.setValue("/authsvc/authenticator/ci/status.html");
}
importPackage(Packages.com.ibm.security.access.ciclient);
importPackage(Packages.com.ibm.security.access.server_connections);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("CI_Common");

/**
 * This mapping rule allows a Cloud Identity user to add or modify
 * authentication methods.
 *
 * Updates to this file will also be made available at:
 *      https://github.com/IBM-Security/isam-civ-integration
 *
 * At this point, support is fully included for: SMS OTP, Email OTP, and TOTP.
 *
 * The main part of this rule forks into different responses based on the request
 * parameter "action". Supported action values are:
 * null || "initiate": Display the already registered auth methods to the user.
 *         Also display a button to allow users to register more methods.
 * "register": Register/enroll a method based on the given type.
 *         For TOTP, enroll the method and return a QR code.
 *         For SMS and Email OTP, enroll the method and return a validation
 *         if required.
 *         For Verify, initiate the registration and return a QR code.
 * "validateOTP": Validate the OTP provided as a request parameter. In some
 *         cases, the enrollment must be validated before it can be used at
 *         runtime for authentication/verification.
 * "remove": Remove the enrollment with the given ID.
 * "update": Update the enrollment with a given ID. This is mainly used to 
 *         enable or disable an auth method.
 */

// The types of methods a user is allowed to complete. Only the types included
// in this list will be displayed to the end user as an authentication option.
// Possible values are: "Verify", "SMSOTP", "EmailOTP", "TOTP"
var enabledMethods = ["SMSOTP", "EmailOTP", "TOTP"];

IDMappingExtUtils.traceString("Entry CI_Self_Care_Rule");

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
    "update_failed"             : macros.get("@UPDATE_FAILED_MSG@"), // "Update failed."
    "update_failed_colon"       : macros.get("@UPDATE_FAILED_COLON_MSG@"), // "Update failed:"
    "removal_failed"            : macros.get("@REMOVAL_FAILED_MSG@"), // "Removal failed."
    "removal_failed_colon"      : macros.get("@REMOVAL_FAILED_COLON_MSG@"), // "Removal failed:"
    "no_type"                   : macros.get("@NO_TYPE_MSG@"), // "No type provided."
    "no_id"                     : macros.get("@NO_ID_MSG@"), // "No ID provided."
    "no_otp"                    : macros.get("@NO_OTP_MSG@"), // "No OTP provided."
    "no_otp_delivery"           : macros.get("@NO_OTP_DELIVERY_MSG@"), // "No OTP delivery detail provided."
    "no_validation_id"          : macros.get("@NO_VALIDATION_ID_MSG@"), // "No validation ID provided."
    "create_transaction_failed" : macros.get("@CREATE_TRANSACTION_FAILED_MSG@"), // "Could not create transacton."
    "create_validation_failed"  : macros.get("@CREATE_VALIDATION_FAILED_MSG@") // "Could not create validation."
};

// The result of the rule. If false, the mapping rule will be run again. If true,
// the next step in the policy is run, if there is one.
var result = false;

// This fetches the server connection saved against the specific auth mechanism
// for this rule.
var conn = ServerConnectionFactory.getCiConnectionById(macros.get("@SERVER_CONNECTION@"));

// This block does early processing of the enabledMethods variable to determine
// which methods should be shown to the user.
var includeTOTP = enabledMethods.indexOf("TOTP") != -1;
var includeSMS = enabledMethods.indexOf("SMSOTP") != -1;
var includeEmail = enabledMethods.indexOf("EmailOTP") != -1;
var someAuthnMethodsEnabled = includeTOTP || includeSMS || includeEmail;
var allAuthnMethodsEnabled = includeTOTP && includeSMS && includeEmail;

// Get the auth status. This will be set by the auth rule in the case where the
// user has to auth before doing a protected action.
var authStatus = getAuthStatus();

// First step is to authenticate the user against CI with their username and
// password. If no username has been supplied as a request parameter, redirect
// to a page requesting it and the password.
var username = getUsername();
var sessionUsername = getUsernameFromSession();
if(username == null) {
    page.setValue("/authsvc/authenticator/ci/login.html");
    macros.put("@ERROR_MESSAGE@", errorMessages["user_not_found"]);
} else {
    // We've been given the username. Check if username/password auth has already
    // been done successfully for this session by fetching basicAuth from the
    // state map.
    var basicAuth = state.get("basicAuth");
    var password = getPassword();
    if(basicAuth == null && sessionUsername == null && password != null) {
        // If we were given the password as well, attempt auth.
        var justAuthed = CiClient.basicAuthentication(conn, username, password, getLocale());
        if(justAuthed) {
            // If successful, save the just authed username as "basicAuth" in
            // the state map.
            basicAuth = username;
            state.put("basicAuth", username);
        } else {
            // Auth failed, reset username.
            username = null;
        }
    }

    // If the user just authed with basicAuth, or authed with ISAM, or the user
    // just performed a CI auth, you may pass!
    if((basicAuth != null && basicAuth == username) || sessionUsername != null ||
        (authStatus != null && (authStatus == "success" || authStatus == "read"))) {
        //First try and get the CI user ID from the state map. If not there, do
        // a lookup of CI to get the user ID.
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
                // method (defined in CI_Common.js).
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

        // Only continue if we have successfully fetched the user ID.
        if(userId != null) {
            // userId or username might not yet be in javascript string form, so
            // convert them now.
            userId = jsString(userId);
            username = jsString(username);

            var action = getAction();

            // If authStatus has been set, and it was a success, we need to
            // override whatever action has carried over from the Auth rule.
            // Also update authStatus such that it can't be read again.
            if(authStatus != null && authStatus == "success") {
                action = "initiate";
                setAuthStatus("read");
            }
            IDMappingExtUtils.traceString("Action: "+action);

            if(action == null || action == "initiate") {
                // Display the already registered auth methods to the user.
                // Also display a button to allow users to register more methods.

                // First clean the state. cleanState is defined in CI_Common.js
                // Check the function definition to confirm which state 
                // variables are cleared.
                cleanState();
                var methods = [];

                // Only make a request to CI to fetch standard auth methods if at
                // least one of either TOTP, SMS OTP or Email OTP is included
                // in enabledMethods
                if(someAuthnMethodsEnabled) {
                    var resp = CiClient.getAuthMethods(conn, userId, getLocale());
                    var json = getJSON(resp);
                    if (resp != null && resp.getCode() == 200 && json != null) {
                        var allMethods = json.authnmethods;

                        // If all methods are included in enabledMethods, just return
                        // the methods array as-is.
                        if(allAuthnMethodsEnabled) {
                            methods = allMethods;
                        } else {
                            // Otherwise, process the returned methods and only pull
                            // out those that are in enabledMethods.
                            for(j = 0; j < allMethods.length; j++) {
                                var method = allMethods[j];
                                if(method["methodType"] == "totp" && includeTOTP) {
                                    methods.push(method);
                                }
                                if(method["methodType"] == "smsotp" && includeSMS) {
                                    methods.push(method);
                                }
                                if(method["methodType"] == "emailotp" && includeEmail) {
                                    methods.push(method);
                                }
                            }
                        }
                    } else {
                        // The request failed. Return an error page via our handleError
                        // method (defined in CI_Common.js).
                        handleError(errorMessages["auth_method_get_failed"], null);
                    }
                }

                // Only make a request to CI to fetch authenticators if Verify
                // is included in enabledMethods
                var authenticators = [];
                if(enabledMethods.indexOf("Verify") != -1) {
                    var resp = CiClient.getAuthenticators(conn, userId, getLocale());
                    var json = getJSON(resp);
                    if (resp != null && resp.getCode() == 200 && json != null) {
                        authenticators = json.authenticators;
                    } else {
                        // The request failed. Return an error page via our handleError
                        // method (defined in CI_Common.js).
                        handleError(errorMessages["auth_method_get_failed"], null);
                    }
                }

                // Now populate all the macros! These macros are how we tell the
                // HTML pages what methods we have available.
                // Also save each method type in the state map.
                macros.put("@AUTH_METHODS@", JSON.stringify(methods));
                macros.put("@METHOD_COUNT@", jsString(methods.length));
                state.put("authMethods", JSON.stringify(methods));

                macros.put("@AUTHENTICATORS@", JSON.stringify(authenticators));
                macros.put("@DEVICE_COUNT@", jsString(authenticators.length));
                state.put("authenticators", JSON.stringify(authenticators));

                macros.put("@ENABLED_METHODS@", JSON.stringify(enabledMethods));
                macros.put("@USERNAME@", username);
                page.setValue("/authsvc/authenticator/ci/usc.html");

                // Log all the methods we fetched.
                IDMappingExtUtils.traceString("CI authentication methods: "+JSON.stringify(methods));
                IDMappingExtUtils.traceString("CI authenticators: "+JSON.stringify(authenticators));
            }
            else if(action == "register") {
                // The user has chosen to register a method or authenticator.
                // Let's process it depending on the method type.
                var type = getType();
                state.put("type", type);

                // If the type is verify, this is a IBM Verify authenticator
                // registration.
                if(type == "verify") {
                    // The registration payload is the owner and the Verify
                    // client ID (configured on the mechanism).
                    var registrationJson = {"owner": userId, "clientId": jsString(macros.get("@VERIFY_CLIENT@"))};

                    var resp = CiClient.registerAuthenticator(conn, JSON.stringify(registrationJson), true, getLocale());
                    var json = getJSON(resp);
                    if (resp != null && resp.getCode() == 200 && json != null) {
                        // Verify registration returns as a QR code. Return it
                        // to the end user for them to scan.
                        macros.put("@QRCODE@", json.b64QRCode);
                        macros.put("@ID@", "");
                        page.setValue("/authsvc/authenticator/ci/verify_registration.html");

                        // Clean the state. cleanState is defined in CI_Common.js
                        // Check the function definition to confirm which state variables
                        // are cleared.
                        cleanState();

                        // Also log an audit event for the successful register.
                        IDMappingExtUtils.logCISelfCareAuditEvent(username, "registerVerify", macros.get("@SERVER_CONNECTION@"), "CI_Self_Care_Rule", "");
                    } else {
                        // The request failed. Log an audit event for it.
                        var code = resp != null ? "" + resp.getCode() : "Verify Registration failed";
                        IDMappingExtUtils.logCISelfCareAuditEvent(username, "registerVerify", macros.get("@SERVER_CONNECTION@"), "CI_Self_Care_Rule", code);
                        // Return an error page via our handleError method
                        // (defined in CI_Common.js).
                        handleError(errorMessages["registration_failed"], resp);
                        // Clean the state. cleanState is defined in CI_Common.js
                        // Check the function definition to confirm which state variables
                        // are cleared.
                        cleanState();
                    }

                } else if(type == "emailotp" || type == "smsotp") {
                    // If the type is email or SMS OTP, the user had to include
                    // an OTP delivery method in the request.
                    var otpDelivery = getOTPDelivery();
                    if(otpDelivery != null) {
                        var enrollmentJson = {"owner": userId, "isEnabled": true, "attributes": {}};
                        if(type == "smsotp") {
                            enrollmentJson.attributes["otpDeliveryMobileNumber"] = otpDelivery;
                        } else {
                            enrollmentJson.attributes["otpDeliveryEmailAddress"] = otpDelivery;
                        }
                        var resp = CiClient.enrollAuthMethod(conn, type, JSON.stringify(enrollmentJson), false, getLocale());
                        var json = getJSON(resp);
                        if (resp != null && (resp.getCode() == 201 || resp.getCode() == 202) && json != null) {
                            // Save the enrollment details to send back to the
                            // USC page.
                            macros.put("@ID@", json.id);
                            macros.put("@LAST_VALIDATION@", "");
                            macros.put("@TYPE@", type);
                            macros.put("@CORRELATION@", "");
                            page.setValue("/authsvc/authenticator/ci/enrollment.html");

                            // If lastValidation is included, we probably have to
                            // do a validation before the user can do an
                            // authentication/verification.
                            if(json.lastValidation == null) {
                                // No last validation, no problem.
                                macros.put("@REQUIRE_VALIDATION@", jsString(false));
                                // Clean the state. cleanState is defined in CI_Common.js
                                // Check the function definition to confirm which state variables
                                // are cleared.
                                cleanState();
                            } else {
                                // Last validation is of the format: /smsotp/06b59d44-4746-41e9-a9fb-05a9eb6d5e9a/validator/8981148e-2cb5-4ca9-9178-3d1da725bcf8
                                // After split we have 5 parts, the first of which is empty. So we want part 4 as the validation IDs.
                                var validationParts = json.lastValidation.split("/");
                                var validationId = validationParts[4];

                                // We have to do a get on the validation to get
                                // the CI generated correlation.
                                var validationResp = CiClient.getValidation(conn, type, json.id, validationId, getLocale());
                                var validationJson = getJSON(validationResp);

                                // Add all our new variables into macros and
                                // the state map.
                                if (validationResp != null && validationResp.getCode() && validationJson != null) {
                                    macros.put("@CORRELATION@", validationJson.correlation);
                                }
                                macros.put("@IS_ENABLED@", jsString(json.isEnabled));
                                macros.put("@CREATION_TIME@", json.creationTime);
                                macros.put("@REQUIRE_VALIDATION@", jsString(true));
                                macros.put("@LAST_VALIDATION@", json.lastValidation);
                                state.put("lastValidation", json.lastValidation);
                                // Also log an audit event for the successful register.
                                IDMappingExtUtils.logCISelfCareAuditEvent(username, "register" + type, macros.get("@SERVER_CONNECTION@"), "CI_Self_Care_Rule", "");
                            }
                        } else {
                            // The request failed. Log an audit event for it.
                            var code = resp != null ? "" + resp.getCode() : type + " registration failed";
                            IDMappingExtUtils.logCISelfCareAuditEvent(username, "register" + type, macros.get("@SERVER_CONNECTION@"), "CI_Self_Care_Rule", code);
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

                } else if(type == "totp") {
                    // TOTP enrollment is similar to Verify, in that a QR code
                    // has to be scanned by the user.

                    // The payload has owner, enabled, and the owner display name.
                    var enrollmentJson = {"owner": userId, "isEnabled": true, "ownerDisplayName": username};
                    var resp = CiClient.enrollAuthMethod(conn, type, JSON.stringify(enrollmentJson), true, getLocale());
                    var json = getJSON(resp);
                    if (resp != null && resp.getCode() == 201 && json != null) {
                        // We got the enrollment QR code. Return it to the end
                        // user for them to scan.

                        macros.put("@QRCODE@", json.attributes.b64QRCode);
                        macros.put("@ID@", json.id);
                        macros.put("@IS_VALIDATED@", jsString(json.isValidated));
                        macros.put("@IS_ENABLED@", jsString(json.isEnabled));
                        macros.put("@CREATION_TIME@", json.creationTime);
                        macros.put("@PERIOD@", jsString(json.attributes.period));
                        macros.put("@DIGITS@", jsString(json.attributes.digits));
                        macros.put("@SECRET@", json.attributes.secret);
                        macros.put("@ALGORITHM@", json.attributes.algorithm);
                        state.put("id", json.id);
                        page.setValue("/authsvc/authenticator/ci/totp_enrollment.html");

                        // Also log an audit event for the successful register.
                        IDMappingExtUtils.logCISelfCareAuditEvent(username, "register" + type, macros.get("@SERVER_CONNECTION@"), "CI_Self_Care_Rule", "");
                    } else {
                        // The request failed. Log an audit event for it.
                        var code = resp != null ? "" + resp.getCode() : type + " registration failed";
                        IDMappingExtUtils.logCISelfCareAuditEvent(username, "register" + type, macros.get("@SERVER_CONNECTION@"), "CI_Self_Care_Rule", code);
                        // Return an error page via our handleError method
                        // (defined in CI_Common.js).
                        handleError(errorMessages["registration_failed"], resp);
                        // Clean the state. cleanState is defined in CI_Common.js
                        // Check the function definition to confirm which state variables
                        // are cleared.
                        cleanState();
                    }

                } else {
                    handleError(errorMessages["registration_failed_colon"] + " " + errorMessages["no_type"], null);
                    // Clean the state. cleanState is defined in CI_Common.js
                    // Check the function definition to confirm which state variables
                    // are cleared.
                    cleanState();
                }
            }
            else if(action == "validateOTP") {
                // Validate the given OTP! This is only valid for TOTP, email,
                // and SMS OTPs.
                // The request has to include the type, ID, validation ID, and OTP.
                var type = getType();
                var id = getId();
                var validationId = getValidationId();
                var lastValidation = getLastValidation();
                var otp = getOTP();

                if(otp != null) {
                    if(type == "smsotp" || type == "emailotp") {
                        // Either lastValidation should be passed in, or ID and
                        // validation ID individually
                        if(lastValidation != null) {
                            // Last validation is of the format: /smsotp/06b59d44-4746-41e9-a9fb-05a9eb6d5e9a/validator/8981148e-2cb5-4ca9-9178-3d1da725bcf8
                            // After split we have 5 parts, the first of which is empty. So we want parts 2 & 4 as the IDs.
                            var validationParts = lastValidation.split("/");
                            id = validationParts[2];
                            validationId = validationParts[4];
                        }
                        if(id != null && validationId != null) {
                            var validationJson = {"otp":otp};

                            var resp = CiClient.validateOTP(conn, type, id, validationId, JSON.stringify(validationJson), getLocale());
                            if (resp != null && resp.getCode() == 200) {
                                // Return a status payload with success.
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
                            // No ID or validation ID was supplied. Return an error
                            // page via our handleError method (defined in CI_Common.js).
                            if(id == null) handleError(errorMessages["validation_failed_colon"] + " " + errorMessages["no_id"], null);
                            else if(validationId == null) handleError(errorMessages["validation_failed_colon"] + " " + errorMessages["no_validation_id"], null);
                        }
                    } else if(type == "totp") {
                        if(id != null) {
                            var validationJson = {"totp":otp};

                            var resp = CiClient.verifyTOTP(conn, id, JSON.stringify(validationJson), getLocale());
                            if (resp != null && resp.getCode() == 200) {
                                // Return a status payload with success.
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
            else if(action == "remove") {
                // Remove the method/authenticator with the given ID. The user
                // also has to chose the type in the request.
                var type = getType();
                var id = getId();

                if(id != null) {
                    if(type == "verify") {
                        // If type is verify, delete the authenticator.
                        var resp = CiClient.deleteAuthenticator(conn, id, getLocale());
                        if (resp != null && resp.getCode() == 204) {
                            // Return a status payload with success.
                            macros.put("@STATUS@", "success");
                            page.setValue("/authsvc/authenticator/ci/status.html");
                            // Clean the state. cleanState is defined in CI_Common.js
                            // Check the function definition to confirm which state variables
                            // are cleared.
                            cleanState();
                        } else {
                            handleError(errorMessages["removal_failed"], resp);
                        }
                    } else if(type == "smsotp" || type == "emailotp" || type == "totp") {
                        // If type is anything else, delete the method.
                        var resp = CiClient.deleteAuthMethod(conn, type, id, getLocale());
                        if (resp != null && resp.getCode() == 204) {
                            // Return a status payload with success.
                            macros.put("@STATUS@", "success");
                            page.setValue("/authsvc/authenticator/ci/status.html");
                            // Clean the state. cleanState is defined in CI_Common.js
                            // Check the function definition to confirm which state variables
                            // are cleared.
                            cleanState();
                        } else {
                            // The request failed. Return an error page via our
                            // handleError method (defined in CI_Common.js).
                            handleError(errorMessages["removal_failed"], resp);
                        }
                    } else {
                        // No type was supplied. Return an error page via our
                        // handleError method (defined in CI_Common.js).
                        handleError(errorMessages["removal_failed_colon"] + " " + errorMessages["no_type"], null);
                    }
                } else {
                    // No ID was supplied. Return an error page via our
                    // handleError method (defined in CI_Common.js).
                    handleError(errorMessages["removal_failed_colon"] + " " + errorMessages["no_id"], null);
                }
            }
            else if(action == "update") {
                // Update the authenticator with the given ID. The user also has
                // to chose the type in the request. But we only support
                // authenticator updates for now.
                var type = getType();
                var id = getId();
                var enabled = getEnabled();

                if(id != null) {
                    if(type == "verify") {
                        var json = {"enabled":enabled};

                        var resp = CiClient.updateAuthenticator(conn, type, id, json, getLocale());
                        if (resp != null && resp.getCode() == 204) {
                            // Clean the state. cleanState is defined in CI_Common.js
                            // Check the function definition to confirm which state variables
                            // are cleared.
                            cleanState();
                        } else {
                            // The request failed. Return an error page via our
                            // handleError method (defined in CI_Common.js).
                            handleError(errorMessages["update_failed"], resp);
                        }
                    } else {
                        // No type was supplied. Return an error page via our
                        // handleError method (defined in CI_Common.js).
                        handleError(errorMessages["update_failed_colon"] + " " + errorMessages["no_type"], null);
                    }
                } else {
                    // No ID was supplied. Return an error page via our
                    // handleError method (defined in CI_Common.js).
                    handleError(errorMessages["update_failed_colon"] + " " + errorMessages["no_id"], null);
                }
            } else {
                // We got another action that wasn't one of our expected ones.
                // Return an error.
                handleError(errorMessages["invalid_action"], null);
            }
        }
    } else if(username != null) {
        macros.put("@USERNAME@", username);
        page.setValue("/authsvc/authenticator/ci/login.html");
    } else {
        // The login request failed. Return an error page via our handleError
        // method (defined in CI_Common.js).
        handleError(errorMessages["login_failed"], null);
    }
}

// Set result. Either true for stop running this rule, or false for run the rule
// again.
success.setValue(result);
IDMappingExtUtils.traceString("Exit CI_Self_Care_Rule");

importPackage(Packages.com.ibm.security.access.scimclient);
importClass(Packages.com.ibm.security.access.recaptcha.RecaptchaClient);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("BranchingHelper");
importMappingRule("USC_Common");

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

IDMappingExtUtils.traceString("Entry USC_Passkey_CollectEmail.js");

var errors = [];
var missing = [];
var rc = true;

// Load the email address and perform some basic verification.
var email = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "emailAddress"));

if (email != "") {
    IDMappingExtUtils.traceString("Read email address: "+email);

    email = jsString(email);

    // Validate the email now.
    if (email != "") {
        var emailRegex = /^([A-Za-z0-9_\-\.])+\@([A-Za-z0-9])+([A-Za-z0-9_\-\.])+\.([A-Za-z]{2,4})$/;
        if (email.length > 5 && email.match(emailRegex)) {
            // Save the email in the session as both email and username for the MAC OTP mechanism.
            context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "email", email);
            context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", email);
        } else {
            errors.push("Email is invalid.");
            rc = false;
        }
        macros.put("@EMAIL@", email);
    } else {
        missing.push("email");
        rc = false;
    }
} else {
    rc = false;
}

// Save whether the browser is UVPA capable in the state, if provided.
var uvpaCapable = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "uvpaCapable"));
if (uvpaCapable != null && uvpaCapable != "") {
    IDMappingExtUtils.traceString("UVPA capable? "+uvpaCapable);
    state.put("uvpaCapable", uvpaCapable === "true");
}

// Check the reCAPTCHA
if (rc == true) {
    var captchaResponse = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "g-recaptcha-response");
    IDMappingExtUtils.traceString("captchaResponse is: "+captchaResponse);

    var captchaVerified = (captchaResponse != null && captchaResponse.trim() != "") && RecaptchaClient.verify(captchaResponse, macros.get("@RECAPTCHASECRETKEY@"), null);
    IDMappingExtUtils.traceString("RecaptchaClient.verify : "+captchaVerified);

    if (captchaVerified == false) {
        errors.push("CAPTCHA Failed.");
        rc = false;
    }
}

// Check if the email address is already in use.
if (rc == true) {
    var resp = ScimClient.httpGet(scimConfig, "/Users?filter=emails.value%20eq%20"+encodeURIComponent(email));
    if (resp != null && resp.getCode() == 200) {
        var respJson = JSON.parse(resp.getBody());
        IDMappingExtUtils.traceString("SCIM resp: "+respJson.totalResults);
        IDMappingExtUtils.traceString("SCIM resp: "+resp.getBody());

        if (respJson.totalResults != 0) {
            errors.push("Email address already in use!");
            rc = false;
        }
    }
}

var errorString = buildErrorString(errors, missing);
if (errorString.length != 0) {
    macros.put("@ERROR_MESSAGE@", errorString);
}

success.setValue(rc);

IDMappingExtUtils.traceString("Exit USC_Passkey_CollectEmail.js");

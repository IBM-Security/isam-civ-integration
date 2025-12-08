// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

// OTPVerify mapping rule.

importClass(Packages.com.tivoli.am.fim.trustserver.sts.uuser.Attribute);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

// Get the STS Universal User attributes and context attributes.

var stsuuAttrs    = stsuu.getAttributeContainer();
var stsuuCtxAttrs = stsuu.getContextAttributesAttributeContainer();

// Clear the STS Universal User attributes. This ensures that the issued TAM credential contains only attributes that are
// explicitly set in this mapping rule.

stsuuAttrs.clear();

// Get the authentication level of the OTP authenticate callback.

var authenticationLevel = stsuuCtxAttrs.getAttributeValueByNameAndType("otp.otp-callback.authentication-level", "otp.otp-callback.type");

// Set the authentication level into STS Universal User attributes. This authentication level will be used as the
// "AUTHENTICATION_LEVEL" attribute in the issued TAM credential.

var attrAuthenticationLevel = new Attribute("AUTHENTICATION_LEVEL", "urn:ibm:names:ITFIM:5.1:accessmanager", authenticationLevel);
stsuuAttrs.setAttribute(attrAuthenticationLevel);

// Get the obligation URI of the OTP authentication callback.

var obligationURI = stsuuCtxAttrs.getAttributeByNameAndType("authenticationTypes", "urn:ibm:names:ITFIM:5.1:accessmanager");

// Set the obligation URI, if any, into STS Universal User attributes. This obligation URI will be used as the
// "authenticationTypes" attribute in the issued TAM credential.

if (obligationURI != null) {
    stsuuAttrs.setAttribute(obligationURI);
}

// Get the OTP type
var otpType = stsuuCtxAttrs.getAttributeValueByNameAndType("otp.sts.otp-method.otp-type", "otp.sts.type");

// Retry enforcement. If the enforcement is enabled, the user is allowed to submit only a limited number of OTPs in OTP Login
// page since the OTP was generated. To enable the enforcement, set isRetryEnforcementEnabled (see below) to true.

var isRetryEnforcementEnabled = true;

if (isRetryEnforcementEnabled && (otpType=="mac_otp") ) {
    var retryCounterID    = "retryCounter";
    var retryCounterValue = IDMappingExtUtils.getSPSSessionData(retryCounterID);
    var retryLimit        = 5;

    // Since this mapping rule is executed every time the OTP is verified, increment the retry counter by one.

    retryCounterValue = parseInt(retryCounterValue) + 1;

    // If the retry counter reaches the retry limit, display the OTP Login page with an error message saying that the user
    // has exceeded the retry limit. If the retry counter exceeds the retry limit, display STS Operation Error page with an
    // error message saying that the user has exceeded the retry limit.

    if (retryCounterValue == retryLimit) {
        // User defined macro. This replaces the macro @MAPPING_RULE_DATA@ in OTP Login page with the specified value.

        var ctxMappingRuleData = new Attribute("@MAPPING_RULE_DATA@", "otp.sts.macro.type", "Retry limit exceeded.");
        stsuuCtxAttrs.setAttribute(ctxMappingRuleData);

        // User defined macro. This replaces the macro @OTP_LOGIN_DISABLED@ in OTP Login page with the specified value,
        // which causes the submit button in that page to be disabled.

        var ctxLoginDisabled = new Attribute("@OTP_LOGIN_DISABLED@", "otp.sts.macro.type", "disabled");
        stsuuCtxAttrs.setAttribute(ctxLoginDisabled);
    } else if (retryCounterValue > retryLimit) {
        IDMappingExtUtils.throwSTSUserMessageException("Retry limit exceeded.");
    }

    // Store the retry counter into SPS session.

    IDMappingExtUtils.setSPSSessionData(retryCounterID, retryCounterValue);
}

// Regenerate enforcement. If the enforcement is enabled, the user is allowed to
// regenerate the OTP only a limited number of times in the OTP Login page. 
// To enable the enforcement, set isRegenerateEnforcementEnabled (see below) to true.
// isRegenerateEnforcementEnabled should also be set to true in otp_generate.js
// This logic is required in the verify mapping rule in order to handle the scenario
// where the "regenerateLimit" has been reached and an incorrect OTP has been submitted. 
var isRegenerateEnforcementEnabled = true;
var regenerateLimit = 5;

if (isRegenerateEnforcementEnabled) {
    // Initialize the DMAP Cache:
    var dmapCache = IDMappingExtUtils.getIDMappingExtCache();

    // Only increment the regenerate counter if it's a regeneration
    // of the same OTP session
    var regenerateCounterID = stsuuCtxAttrs
            .getAttributeValueByName("otp.sts.otp-session.id");

    IDMappingExtUtils
            .traceString("OTPGenerate:Regenerate. Current OTP Session ID : "
                    + regenerateCounterID);

    // Set initial counter to -1 since first load of page will increment 
    // the counter
    var currentCounter = -1;

    // Check for a current counter in the SPS Session Data and fetch the
    // incremented value
    if (dmapCache.exists(regenerateCounterID)) {
        currentCounter = dmapCache.get(regenerateCounterID);
    }
    IDMappingExtUtils
    .traceString("OTPGenerate:Regenerate. Counter before incrementing : "
            + currentCounter);
    currentCounter = parseInt(currentCounter) + 1;
    IDMappingExtUtils
    .traceString("OTPGenerate:Regenerate. Counter after incrementing: "
            + currentCounter);
    
    // If "regenerateLimit" has not been reached, store the new incremented
    // counter value; else, disable the "Regenerate" button
    if (currentCounter < regenerateLimit) {
        // Increment the counter as this will be counted as a regeneration
        // attempt.
        dmapCache.put(regenerateCounterID, currentCounter, 3600);

    } else if (currentCounter >= regenerateLimit) {
        // If "regenerateLimit" has been reached, set appropriate messages and
        // disable the "Regenerate" button. 
        IDMappingExtUtils
                .traceString("OTPGenerate:Regenerate. Counter reached max : "
                        + currentCounter);
        var ctxMappingRuleData = new Attribute("@MAPPING_RULE_DATA@",
                "otp.sts.macro.type", "Regeneration limit exceeded.");
        stsuuCtxAttrs.setAttribute(ctxMappingRuleData);

        // User defined macro. This replaces the macro @OTP_REGENERATE_DISABLED@
        // in OTP Login page with the specified value,
        // which causes the regenerate button in that page to be disabled.
        var ctxRegenerateDisabled = new Attribute("@OTP_REGENERATE_DISABLED@",
                "otp.sts.macro.type", "disabled");
        stsuuCtxAttrs.setAttribute(ctxRegenerateDisabled);
        dmapCache.put(regenerateCounterID, currentCounter, 3600);
    }
}
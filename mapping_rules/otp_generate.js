// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

// OTPGenerate mapping rule.

importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.uuser.Attribute);

// Retry enforcement. If the enforcement is enabled, the user is allowed to
// submit only a limited number of OTPs in OTP Login
// page since the OTP was generated. To enable the enforcement, set
// isRetryEnforcementEnabled (see below) to true.

var isRetryEnforcementEnabled = true;

var stsuuAttrs = stsuu.getAttributeContainer();
var stsuuCtxAttrs = stsuu.getContextAttributesAttributeContainer();

// Regenerate enforcement. If the enforcement is enabled, the user is allowed to
// regenerate the OTP only a limited number of times in the OTP Login page. 
// To enable the enforcement, set isRegenerateEnforcementEnabled (see below) to true.
var isRegenerateEnforcementEnabled = true;
var regenerateLimit = 5;

if (isRetryEnforcementEnabled) {
    // Since this mapping rule is executed everytime an OTP is generated, set
    // the retry counter to zero.

    var retryCounterID = "retryCounter";
    var retryCounterValue = "0";

    // Store the retry counter into SPS session.

    IDMappingExtUtils.setSPSSessionData(retryCounterID, retryCounterValue);
}

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
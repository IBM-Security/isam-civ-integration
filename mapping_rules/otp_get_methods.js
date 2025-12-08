// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

// OTPGetMethods mapping rule.

importClass(Packages.com.tivoli.am.fim.trustserver.sts.uuser.Attribute);

// Get the STS Universal User attributes and context attributes.

var stsuuAttrs    = stsuu.getAttributeContainer();
var stsuuCtxAttrs = stsuu.getContextAttributesAttributeContainer();

// Generate a list of OTP methods. OTP method represents a method used to generate, deliver, and verify the OTP.  

var methods = [];

var useSMS   = true;
var useEmail = true;
var useTOTP  = true;
var useHOTP  = true;
var useRSA   = true;

if (useSMS) {
    var mobileNumber = "+12345678";
    // var mobileNumber = stsuuAttrs.getAttributeValueByName("tagvalue_phone");

    methods.push({
        id                : "sms",
        otpType           : "mac_otp",
        deliveryType      : "sms_delivery",
        deliveryAttribute : mobileNumber,
        userInfoType      : "",
        label             : "SMS to " + maskPhone(mobileNumber)
    });
}

if (useEmail) {
    var emailAddress = "user@localhost";
    // var emailAddress = stsuuAttrs.getAttributeValueByName("tagvalue_email");

    methods.push({
        id                : "email",
        otpType           : "mac_otp",
        deliveryType      : "mail_delivery",
        deliveryAttribute : emailAddress,
        userInfoType      : "",
        label             : "Email to " + maskEmail(emailAddress)
	});
}

if (useTOTP) {
    methods.push({
        id                : "totp",
        otpType           : "totp_otp",
        deliveryType      : "no_delivery",
        deliveryAttribute : "",
        userInfoType      : "jdbc_userinfo",
        label             : "Time Based OTP"
    });
}

if (useHOTP) {
    methods.push({
        id                : "hotp",
        otpType           : "hotp_otp",
        deliveryType      : "no_delivery",
        deliveryAttribute : "",
        userInfoType      : "jdbc_userinfo",
        label             : "Counter Based OTP"
    });
}

if (useRSA) {
    methods.push({
	    id                : "rsa",
        otpType           : "rsa_otp",
        deliveryType      : "no_delivery",
        deliveryAttribute : "",
        userInfoType      : "",
        label             : "RSA Token"
    });
}

// Set the list of OTP methods into STS Universal User context attributes. The list is transformed into a set of arrays before
// it is set into STS Universal User context attributes.

var methodIds                = [];
var methodOTPTypes           = [];
var methodDeliveryTypes      = [];
var methodDeliveryAttributes = [];
var methodLabels             = [];
var methodUserInfoTypes      = [];

for (var i = 0; i < methods.length; i++) {
    methodIds[i]                = methods[i].id;
    methodOTPTypes[i]           = methods[i].otpType;
    methodDeliveryTypes[i]      = methods[i].deliveryType;
    methodDeliveryAttributes[i] = methods[i].deliveryAttribute;
    methodLabels[i]             = methods[i].label;
    methodUserInfoTypes[i]      = methods[i].userInfoType;
}

var ctxMethodIds                = new Attribute("otp.sts.otp-method.ids",                 "otp.sts.type", jsToJavaArray(methodIds));
var ctxMethodOTPTypes           = new Attribute("otp.sts.otp-method.otp-types",           "otp.sts.type", jsToJavaArray(methodOTPTypes));
var ctxMethodDeliveryTypes      = new Attribute("otp.sts.otp-method.delivery-types",      "otp.sts.type", jsToJavaArray(methodDeliveryTypes));
var ctxMethodDeliveryAttributes = new Attribute("otp.sts.otp-method.delivery-attributes", "otp.sts.type", jsToJavaArray(methodDeliveryAttributes));
var ctxMethodLabels             = new Attribute("otp.sts.otp-method.labels",              "otp.sts.type", jsToJavaArray(methodLabels));
var ctxMethodUserInfoTypes      = new Attribute("otp.sts.otp-method.user-info-types",     "otp.sts.type", jsToJavaArray(methodUserInfoTypes));

stsuuCtxAttrs.setAttribute(ctxMethodIds);
stsuuCtxAttrs.setAttribute(ctxMethodOTPTypes);
stsuuCtxAttrs.setAttribute(ctxMethodDeliveryTypes);
stsuuCtxAttrs.setAttribute(ctxMethodDeliveryAttributes);
stsuuCtxAttrs.setAttribute(ctxMethodLabels);
stsuuCtxAttrs.setAttribute(ctxMethodUserInfoTypes);

// Method for converting JavaScript array into Java array.

function jsToJavaArray(jsArray) {
    var javaArray = java.lang.reflect.Array.newInstance(java.lang.String, jsArray.length);
    for (var i = 0; i < jsArray.length; i++) {
        javaArray[i] = jsArray[i];
    }

    return javaArray;
}
function maskPhone(number) {
    var masked = "";
    for(j = 0; j < number.length; j++) {
        if(number[j] == "+") {
            masked += number[j];
        } else if(j > number.length - 4) {
            masked += number[j];
        } else if(!masked.includes('*')) {
            // Lets not indicate how long the phone number is
            masked += '******';
        }
    }
    return masked;
}
function maskEmail(email) {
    var masked = "";
    var atIndex = email.length;
    for(j = 0; j < email.length; j++) {
        if(email[j] == "@") {
            atIndex = j;
            masked += email[j];
        } else if(j > atIndex) {
            masked += email[j];
        } else if(j < 3) {
            masked += email[j];
        } else if(!masked.includes('*')) {
            // Lets not indicate how long the email is
            masked += '******';
        }
    }
    return masked;
}
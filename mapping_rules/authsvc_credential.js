// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

// AuthSvcCredential mapping rule.

// You can use this mapping rule to modify the current user credential. To this
// end, Authentication Service provides two implicit objects. The first object
// is "stsuu", which represents the current user credential. The second object
// is "context", which you can use to retrieve various attributes.

// "stsuu" is an instance of STSUniversalUser Java class. You can find the
// javadoc of this class in Local Management Interface under Manage (System
// Settings) >> Secure Settings >> File Downloads. In File Downloads panel,
// download IVIA-javadoc.zip under mga >> doc. The javadoc of STSUniversalUser
// class is located under com.tivoli.am.fim.sts directory. 

// To retrieve an attribute from "context", you can invoke its "get" method by
// passing the scope, the namespace, and the name of the attribute. There are
// two scopes: session and request. To get attribute from session scope, pass
// "Scope.SESSION" as the scope. And to get attribute from request scope, pass
// "Scope.REQUEST" as the scope. The list of attributes that you can retrieve
// can be found in the product documentation.

// Uncomment the code below to see how the mapping rule affects the current
// user credential.

importClass(Packages.com.tivoli.am.fim.trustserver.sts.uuser.Attribute);

var stsuuAttrs = stsuu.getAttributeContainer();
var policyID = context.get(Scope.SESSION, "urn:ibm:security:asf:policy", "policyID");

if (policyID.equals("urn:ibm:security:authentication:asf:password")) {
    // Add attribute "authenticatedBy" with value "IBM Verify Identity Access"
    // to the current user credential.
    stsuuAttrs.setAttribute(new Attribute("authenticatedBy", null, "IBM Verify Identity Access"));
    
    /**
    * OIDC Conformance-Example 1.1.1
    * Setting the date attribute for max_age scenario.
    * This helps in obtaining the current time.
    * (new Date()).getTime() -> returns epoc time in UTC by default
    **/
    stsuu.addAttribute(new Attribute("AZN_CRED_AUTH_EPOCH_TIME", null, (new Date()).getTime()));

}

/*
var isTwoFactorPolicy = false;

if (policyID.equals("urn:ibm:security:authentication:asf:password_emailotp")) {
    isTwoFactorPolicy = true;
} else if (policyID.equals("urn:ibm:security:authentication:asf:password_smsotp")) {
    isTwoFactorPolicy = true;
} else if (policyID.equals("urn:ibm:security:authentication:asf:password_macotp")) {
    isTwoFactorPolicy = true;
} else if (policyID.equals("urn:ibm:security:authentication:asf:password_hotp")) {
    isTwoFactorPolicy = true;
} else if (policyID.equals("urn:ibm:security:authentication:asf:password_totp")) {
    isTwoFactorPolicy = true;
} else if (policyID.equals("urn:ibm:security:authentication:asf:password_rsa")) {
    isTwoFactorPolicy = true;
} else if (policyID.equals("urn:ibm:security:authentication:asf:password_otp")) {
    isTwoFactorPolicy = true;
} else {
    isTwoFactorPolicy = false;
}

if (isTwoFactorPolicy) {
    // Add attribute "isTwoFactorPolicy" with value "true" to the current user
    // credential.
    stsuuAttrs.setAttribute(new Attribute("isTwoFactorPolicy", null, "true"));
} else {
    // Add attribute "isTwoFactorPolicy" with value "false" to the current user
    // credential.
    stsuuAttrs.setAttribute(new Attribute("isTwoFactorPolicy", null, "false"));
}

*/

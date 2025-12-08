importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

/*
 * This rule is to be used within an InfoMap authentication mechanism to
 * validate the authentication state before allowing a user to register
 * or modify their U2F registrations.
 *
 * By default - it will not do any special authorization checks, but it shows
 * some simple examples of how an administrator might check that a user
 * has satisfied certain authentication pre-requisites. 
 */

/*
 * The users authentication level must be greater than or equal to:
 */
var requiredAuthLevel = 1;

/*
 * When using an AAC Authentication Service, the completion of a mechanism
 * can be mandated in order to access the registration.
 * For example: "urn:ibm:security:authentication:asf:mechanism:otp"
 * 
 * A value of blank - disables this check.
 *
 * The user must have authenticated with the following mechanism:
 */
var requiredAuthMechanism = "";

var returnCode = true;
var errorMessage = "";

var completedAuthMechs = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "authenticationMechanismTypes");
var userAuthLevelStr = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "AUTHENTICATION_LEVEL");

var userAuthLevelInt = 0;
if (userAuthLevelStr != null)
{
    userAuthLevelInt = parseInt(userAuthLevelStr);
}

if (requiredAuthLevel <= userAuthLevelInt)
{
    if (requiredAuthMechanism != "")
    {
        if (requiredAuthMechanism != null)
        {
            //Loop through completed mechanisms,
            //See if they have satisfied the required mech.
            
            if (completedAuthMechs != null && completedAuthMechs.indexOf(requiredAuthMechanism) != -1)
            {
                
            } else
            {
                returnCode = false;
                errorMessage = "Insufficient Authentication. Two Factor Authentication Registration mandates the authentication mechanism - " + requiredAuthMechanism;
            }
            
        } else {
            returnCode = false;
            errorMessage = "Insufficient Authentication. Two Factor Authentication Registration mandates the authentication mechanism - " + requiredAuthMechanism;
        }
    }
} else
{
    returnCode = false;
    errorMessage = "Insufficient Authentication Level. Two Factor Authentication Registration mandates an Authentication Level of " + requiredAuthLevel;  
}

macros.put("@ERROR_MESSAGE@",errorMessage);
success.setValue(returnCode);
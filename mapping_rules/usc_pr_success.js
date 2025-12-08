/*********************************************************************
 * Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.
 *
 *   Licensed Materials - Property of IBM
 *   (C) Copyright IBM Corp. 2016. All Rights Reserved
 *
 *   US Government Users Restricted Rights - Use, duplication, or
 *   disclosure restricted by GSA ADP Schedule Contract with
 *   IBM Corp.
 *********************************************************************/

importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

IDMappingExtUtils.traceString("entry USC_PasswordReset_Success.js");

/*
 * Populate the page macros.
 */

var username = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username");
var firstName = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "firstName");

IDMappingExtUtils.traceString("populating macros:");
IDMappingExtUtils.traceString("@USERNAME@ = "+username);
IDMappingExtUtils.traceString("@FIRSTNAME@ = "+firstName);

macros.put("@USERNAME@", username);
macros.put("@FIRSTNAME@", firstName);

/*
 * Indicate to the AuthSvc that we are finished and do not want to create a session.
 */

success.endPolicyWithoutCredential();

IDMappingExtUtils.traceString("exit USC_PasswordReset_Success.js");

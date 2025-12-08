importClass(Packages.com.tivoli.am.fim.saml.misc.Saml20ObjectFactory);
importClass(Packages.com.tivoli.am.fim.saml.protocol.Saml20IDPList);
importClass(Packages.com.tivoli.am.fim.saml.protocol.Saml20Scoping);
importClass(Packages.com.tivoli.am.fim.saml.protocol.Saml20IDPEntry);
importClass(Packages.com.tivoli.am.fim.saml.protocol.Saml20AuthnRequest);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.uuser);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.utilities);

/*
This sample mapping rule can be used to include SAML2.0 scoping into the authentication request.
*/
IDMappingExtUtils.traceString("Authentication Request MappingRule to add scoping");


var objFactory = Saml20ObjectFactory.getInstance();
var idpList = objFactory.createSamlIDPList();
var idpEntry = objFactory.createSamlIDPEntry();
//ProviderID example is www.myidp.ibm.com
idpEntry.setProviderID("www.myidp.ibm.com");
//ProviderName example is IBM
idpEntry.setProviderName("IBM");
//Location example is ExampleLocation
idpEntry.setLoc("ExampleLocation");
idpList.addIDPEntry(idpEntry);
var scopingObj = objFactory.createSamlScoping();
scopingObj.setIDPList(idpList);
authnrequest.setScoping(scopingObj);


-include= ~${workspace}/cnf/resources/bnd/feature.props
symbolicName=com.ibm.websphere.appserver.constrainedDelegation-1.0
visibility=public
singleton=true
IBM-ShortName: constrainedDelegation-1.0
IBM-API-Package: com.ibm.websphere.security.s4u2proxy; type="ibm-api"
Subsystem-Name: Kerberos Constrained Delegation for SPNEGO 1.0
-features=com.ibm.websphere.appserver.appSecurity-2.0; ibm.tolerates:=3.0
-bundles=com.ibm.ws.security.kerberos.java8
-jars=com.ibm.websphere.appserver.api.constrainedDelegation; location:=dev/api/ibm/
-files=dev/api/ibm/javadoc/com.ibm.websphere.appserver.api.constrainedDelegation_1.0-javadoc.zip

kind=ga
edition=core

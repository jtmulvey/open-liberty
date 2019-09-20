-include= ~${workspace}/cnf/resources/bnd/feature.props
symbolicName=com.ibm.websphere.appserver.channelfw-1.0
IBM-API-Package: com.ibm.websphere.endpoint; type="ibm-api"
IBM-Process-Types: server, \
 client
-bundles=com.ibm.ws.timer, \
 com.ibm.ws.channelfw, \
 com.ibm.ws.org.jose4j.0.5.1; version="[1.0.0,1.0.200)", \
 com.ibm.ws.com.google.gson.2.2.4; version="[1.0.0,1.0.200)", \
 com.ibm.ws.org.slf4j.api.1.7.7; version="[1.0.0,1.0.200)", \
 com.ibm.ws.org.slf4j.jdk14.1.7.7; version="[1.0.0,1.0.200)", \
 com.ibm.ws.org.bcprov.jdk15on.1.60, \
 com.ibm.ws.org.bcpkix.jdk15on.1.60
 -features=com.ibm.websphere.appserver.javax.annotation-1.1; ibm.tolerates:="1.2, 1.3"
-jars=com.ibm.websphere.appserver.api.endpoint; location:=dev/api/ibm/
-files=dev/api/ibm/javadoc/com.ibm.websphere.appserver.api.endpoint_1.0-javadoc.zip
kind=ga
edition=core
WLP-Activation-Type: parallel

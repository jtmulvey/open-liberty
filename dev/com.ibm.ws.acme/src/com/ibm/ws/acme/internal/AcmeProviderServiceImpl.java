/*******************************************************************************
 * Copyright (c) 2014, 2015, 2017 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.acme.internal;

import java.util.Dictionary;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;
import java.io.File;
import java.io.IOException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.security.KeyPair;
import java.security.Security;
import java.util.Collection;
import java.util.Arrays;
import java.util.ArrayList;
import java.net.URI;

import javax.servlet.ServletContainerInitializer;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;

import java.util.concurrent.ExecutorService;


import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;

import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.ws.config.xml.internal.nester.Nester;
import com.ibm.ws.webcontainer.webapp.WebAppConfigExtended;
import com.ibm.wsspi.webcontainer.metadata.WebModuleMetaData;
import com.ibm.wsspi.webcontainer.servlet.IServletContext;
import com.ibm.wsspi.webcontainer.webapp.WebAppConfig;
import com.ibm.wsspi.kernel.service.utils.ConcurrentServiceReferenceMap;

import com.ibm.ws.acme.config.AcmeConfig;;
import com.ibm.ws.acme.config.AcmeService;
import com.ibm.ws.acme.web.AcmeAuthorizationServices;


import com.ibm.ws.acme.internal.org.shredzone.acme4j.*;
import com.ibm.ws.acme.internal.org.shredzone.acme4j.Certificate.*;
import com.ibm.ws.acme.internal.org.shredzone.acme4j.Order.*;
import com.ibm.ws.acme.internal.org.shredzone.acme4j.challenge.*;
import com.ibm.ws.acme.internal.org.shredzone.acme4j.connector.*;
import com.ibm.ws.acme.internal.org.shredzone.acme4j.exception.*;
import com.ibm.ws.acme.internal.org.shredzone.acme4j.provider.*;
import com.ibm.ws.acme.internal.org.shredzone.acme4j.util.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 * ACME certificate management support.
 */
@Component(service= { AcmeConfig.class, ServletContainerInitializer.class, ServletContextListener.class }, 
		immediate = true,
        configurationPolicy = ConfigurationPolicy.REQUIRE,
        configurationPid = "com.ibm.ws.acme.config",
        property = "service.vendor=IBM")
public class AcmeProviderServiceImpl implements AcmeConfig,  ServletContextListener, ServletContainerInitializer {
	
    private final TraceComponent tc = Tr.register(AcmeProviderServiceImpl.class);
    private String parameter1 = "JM-acme-parm1";
    private String parameter2 = "JM-acme-parm2";
    
    private AcmeService serviceProvider;

    /**
     * The properties class that contain the attributes defined
     * by inside of server.xml.
     */
    private final Properties sessionProperties = new Properties();
    /**
     * Strings used to access the various attributes that are
     * defined in the <mailSession> and that are subsequently
     * extracted from the ComponentContext to be placed in the Properties
     * object
     */
    public static final String PARM1 = "configParm1";
    public static final String PARM2 = "configParm2";
    
    private final String propertiesArray[] = { PARM1, PARM2 };
    
    private final HashMap<String, Set<String>> appModules = new HashMap<String, Set<String>>();   
    
    // File name of the User Key Pair
    private static final File USER_KEY_FILE = new File("user.key");

    // File name of the Domain Key Pair
    private static final File DOMAIN_KEY_FILE = new File("domain.key");

    // File name of the CSR
    private static final File DOMAIN_CSR_FILE = new File("domain.csr");

    // File name of the signed certificate
    private static final File DOMAIN_CHAIN_FILE = new File("domain-chain.crt");

    //Challenge type to be used
    private static final ChallengeType CHALLENGE_TYPE = ChallengeType.HTTP;

    // RSA key size of generated key pairs
    private static final int KEY_SIZE = 2048;

    private enum ChallengeType { HTTP, DNS }
    
     //@Activate
    protected void activate(ComponentContext context, Map<String, Object> properties) {
    	Tr.info(tc, "******* JTM ******* AcmeProviderServiceImpl: inside activate() method. Display input properties: ");
    	
    	for(String key: properties.keySet())
    	    Tr.info(tc, "******* JTM ******* AcmeProviderServiceImpl: " + key + " - " + properties.get(key));
    	
    	BundleContext bndcontext = context.getBundleContext();
    	
        ServiceReference<ExecutorService> executorRef = bndcontext.getServiceReference(ExecutorService.class);
        ExecutorService executor = executorRef == null ? null : bndcontext.getService(executorRef);
        if (executor == null) {
            // This is unexpected that the executor service is not available by this point.
    	    Tr.info(tc, "******* JTM ******* AcmeProviderServiceImpl: Unable to get Executor!!");
        } else {
            executor.execute(new Runnable() {
                @Override
                public void run() {
             	    Tr.info(tc, "******* JTM ******* AcmeProviderServiceImpl: Call LetsEncrypt on separate thread!");
                    Tr.info(tc, "******* JTM ******* AcmeProviderServiceImpl: call certificate factory - using LetsEncrypt!");
                    
                    Security.addProvider(new BouncyCastleProvider());
                        
                    Collection<String> domains = 
                    	    new ArrayList<String>(Arrays.asList(new String[] { "jmulvey.wascloud.net", "jmulvey.wascloud.net" }));

                    try {
                       fetchCertificate(domains);
                    }
                    catch (Exception ex) {
                      Tr.error(tc, "******* JTM ******* AcmeProviderServiceImpl: Failed to get a certificate for domains " + domains, ex);
                    }
               }
            });
            bndcontext.ungetService(executorRef);
        }
	
    }

    //@Modified
    protected void modify(Map<String, Object> properties) {
    	Tr.info(tc, " ******* JTM ******* AcmeProviderServiceImpl: inside modified () method");
    }

    //@Deactivate
    protected void deactivate(ComponentContext context, int reason) {
      	Tr.info(tc, " ******* JTM ******* AcmeProviderServiceImpl: inside deactivate() method");
    }

    /** {@inheritDoc} */
    @Override
    public void onStartup(java.util.Set<java.lang.Class<?>> c, ServletContext ctx) throws ServletException {
    	Tr.info(tc, " ******* JTM ******* AcmeProviderServiceImpl: entered ServletContext onStartup() method");
     }
    
    /** {@inheritDoc} */
    @Override
    public void contextDestroyed(ServletContextEvent cte) {
    	Tr.info(tc, "**** JTM **** AcmeProviderServiceImpl: entered ServletContextListener contextDestroyed() for application: "+cte.getServletContext().getServletContextName());
    	// AcmeProviderServiceImpl.moduleStopped(appmodname);
    }

    /** {@inheritDoc} */
    @Override
    public void contextInitialized(ServletContextEvent cte) {
    	Tr.info(tc, "******* JTM ******* AcmeProviderServiceImpl: entered ServletContextListener contextInitialized() for application: "+cte.getServletContext().getServletContextName());
    }
    
    @Override
    public String getParameter1() {
        return parameter1;
    }

    @Override
    public String getParameter2() {
        return parameter2;
    }
    
    /**
     * Generates a certificate for the given domains. Also takes care for the registration
     * process.
     *
     * @param domains
     *            Domains to get a common certificate for
     */
    public void fetchCertificate(Collection<String> domains) throws IOException, AcmeException {
        // Load the user key file. If there is no key file, create a new one.
    	Tr.info(tc, "JTM Inside fetchCertificate");
    	
        //try {  // Wait for a few seconds
        //	Tr.info(tc, "******************* JTM ************** WAIT BEFORE CALLING LETSENCRYPT ************");
        //	Thread.sleep(5000L);
    	//} catch (InterruptedException ex) {
    	//	Tr.error(tc, "JTM: LetsEncrypt call interrupted");
    	//	Thread.currentThread().interrupt();
    	//}
    	
    	Tr.info(tc, "JTM fetchCertificate loadOrCreateUserKeyPair()");

    	KeyPair userKeyPair = loadOrCreateUserKeyPair();

        // Create a session for Let's Encrypt.
        // Use "acme://letsencrypt.org" for production server
    	Tr.info(tc, "JTM fetchCertificate new session");
        Session session = new Session("https://acme-staging-v02.api.letsencrypt.org/directory");

        // Get the Account.
        // If there is no account yet, create a new one.
    	Tr.info(tc, "JTM fetchCertificate findOrRegisterAccount()");
        Account acct = findOrRegisterAccount(session, userKeyPair);

        // Load or create a key pair for the domains. This should not be the userKeyPair!
    	Tr.info(tc, "JTM fetchCertificate loadOrCreateKeyPair()");
        KeyPair domainKeyPair = loadOrCreateDomainKeyPair();

        // Order the certificate
    	Tr.info(tc, "JTM fetchCertificate order certificate");
        Order order = acct.newOrder().domains(domains).create();

        // Perform all required authorizations
    	Tr.info(tc, "JTM fetchCertificate call getAuthorizations");
        for (Authorization auth : order.getAuthorizations()) {
            authorize(auth);
        }

        // Generate a CSR for all of the domains, and sign it with the domain key pair.
    	Tr.info(tc, "JTM fetchCertificate generate CSR");
        CSRBuilder csrb = new CSRBuilder();
        csrb.addDomains(domains);
        csrb.sign(domainKeyPair);

        // Write the CSR to a file, for later use.
    	Tr.info(tc, "JTM write CSR to file: "+DOMAIN_CSR_FILE);
        try (Writer out = new FileWriter(DOMAIN_CSR_FILE)) {
            csrb.write(out);
        }

        // Order the certificate
    	Tr.info(tc, "JTM order certificate");
        order.execute(csrb.getEncoded());

        // Wait for the order to complete
        try {
        	Tr.info(tc, "JTM wait for order to complete...");
            int attempts = 10;
            while (order.getStatus() != Status.VALID && attempts-- > 0) {
                // Did the order fail?
                if (order.getStatus() == Status.INVALID) {
                    throw new AcmeException("Order failed... Giving up.");
                }

                // Wait for a few seconds
            	Tr.info(tc, "******************* JTM ******************** ORDER WAITING 3 SECS BEFORE RETRY ************");
                Thread.sleep(3000L);

                // Then update the status
                order.update();
            }
        } catch (InterruptedException ex) {
            Tr.error(tc, "JTM: order interrupted");
            Thread.currentThread().interrupt();
        }

        // Get the certificate
        com.ibm.ws.acme.internal.org.shredzone.acme4j.Certificate certificate = order.getCertificate();
        
        Tr.info(tc, "Success! The certificate for domains " + domains + " has been generated!");
        Tr.info(tc, "Certificate URL: " + certificate.getLocation());

        // Write a combined file containing the certificate and chain.
        try (FileWriter fw = new FileWriter(DOMAIN_CHAIN_FILE)) {
            certificate.writeCertificate(fw);
        }

        // That's all! Configure your web server to use the DOMAIN_KEY_FILE and
        // DOMAIN_CHAIN_FILE for the requested domans.
    }

    /**
     * Loads a user key pair from {@value #USER_KEY_FILE}. If the file does not exist,
     * a new key pair is generated and saved.
     * <p>
     * Keep this key pair in a safe place! In a production environment, you will not be
     * able to access your account again if you should lose the key pair.
     *
     * @return User's {@link KeyPair}.
     */
    private KeyPair loadOrCreateUserKeyPair() throws IOException {
        if (USER_KEY_FILE.exists()) {
            // If there is a key file, read it
            try (FileReader fr = new FileReader(USER_KEY_FILE)) {
                return KeyPairUtils.readKeyPair(fr);
            }

        } else {
            // If there is none, create a new key pair and save it
            KeyPair userKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
            try (FileWriter fw = new FileWriter(USER_KEY_FILE)) {
                KeyPairUtils.writeKeyPair(userKeyPair, fw);
            }
            return userKeyPair;
        }
    }

    /**
     * Loads a domain key pair from {@value #DOMAIN_KEY_FILE}. If the file does not exist,
     * a new key pair is generated and saved.
     *
     * @return Domain {@link KeyPair}.
     */
    private KeyPair loadOrCreateDomainKeyPair() throws IOException {
        if (DOMAIN_KEY_FILE.exists()) {
            try (FileReader fr = new FileReader(DOMAIN_KEY_FILE)) {
                return KeyPairUtils.readKeyPair(fr);
            }
        } else {
            KeyPair domainKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
            try (FileWriter fw = new FileWriter(DOMAIN_KEY_FILE)) {
                KeyPairUtils.writeKeyPair(domainKeyPair, fw);
            }
            return domainKeyPair;
        }
    }

    /**
     * Finds your {@link Account} at the ACME server. It will be found by your user's
     * public key. If your key is not known to the server yet, a new account will be
     * created.
     * <p>
     * This is a simple way of finding your {@link Account}. A better way is to get the
     * URL and KeyIdentifier of your new account with {@link Account#getLocation()}
     * {@link Session#getKeyIdentifier()} and store it somewhere. If you need to get
     * access to your account later, reconnect to it via
     * {@link Account#bind(Session, URI)} by using the stored location.
     *
     * @param session
     *            {@link Session} to bind with
     * @return {@link Login} that is connected to your account
     */
    private Account findOrRegisterAccount(Session session, KeyPair accountKey) throws AcmeException {
        // Ask the user to accept the TOS, if server provides us with a link.
        URI tos = session.getMetadata().getTermsOfService();
        //if (tos != null) {
        //   acceptAgreement(tos);
        //}

        Account account = new AccountBuilder()
                        .agreeToTermsOfService()
                        .useKeyPair(accountKey)
                        .create(session);
        Tr.info(tc, "Registered a new user, URL: " + account.getLocation());
        
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
        
        return account;
    }

    /**
     * Authorize a domain. It will be associated with your account, so you will be able to
     * retrieve a signed certificate for the domain later.
     *
     * @param auth
     *            {@link Authorization} to perform
     * @throws IOException 
     */
    private void authorize(Authorization auth) throws AcmeException, IOException {
        Tr.info(tc, "Authorization for domain " + auth.getDomain());

        // The authorization is already valid. No need to process a challenge.
        if (auth.getStatus() == Status.VALID) {
            return;
        }

        // Find the desired challenge and prepare it.
        Challenge challenge = null;
        switch (CHALLENGE_TYPE) {
            case HTTP:
                challenge = httpChallenge(auth);
                break;

            case DNS:
                challenge = dnsChallenge(auth);
                break;
        }

        if (challenge == null) {
            throw new AcmeException("No challenge found");
        }

        // If the challenge is already verified, there's no need to execute it again.
        if (challenge.getStatus() == Status.VALID) {
            return;
        }

        // Now trigger the challenge.
        challenge.trigger();

        // Poll for the challenge to complete.
        try {
            int attempts = 10;
            while (challenge.getStatus() != Status.VALID && attempts-- > 0) {
                // Did the authorization fail?
                if (challenge.getStatus() == Status.INVALID) {
                    throw new AcmeException("Challenge failed... Giving up.");
                }

                // Wait for a few seconds
            	Tr.info(tc, "******************* JTM ******************** CHALLENGE WAITING 5 SECS BEFORE RETRY ************");
                Thread.sleep(5000L);

                // Then update the status
                challenge.update();
            }
        } catch (InterruptedException ex) {
            Tr.error(tc, "JTM: challenge interrupted", ex);
            Thread.currentThread().interrupt();
        }

        // All reattempts are used up and there is still no valid authorization?
        if (challenge.getStatus() != Status.VALID) {
            throw new AcmeException("Failed to pass the challenge for domain "
                    + auth.getDomain() + ", ... Giving up.");
        }
    }

    /**
     * Prepares a HTTP challenge.
     * <p>
     * The verification of this challenge expects a file with a certain content to be
     * reachable at a given path under the domain to be tested.
     * <p>
     * This example outputs instructions that need to be executed manually. In a
     * production environment, you would rather generate this file automatically, or maybe
     * use a servlet that returns {@link Http01Challenge#getAuthorization()}.
     *
     * @param auth
     *            {@link Authorization} to find the challenge in
     * @return {@link Challenge} to verify
     * @throws IOException 
     */
    public Challenge httpChallenge(Authorization auth) throws AcmeException, IOException {
        // Find a single http-01 challenge
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
        if (challenge == null) {
            throw new AcmeException("Found no " + Http01Challenge.TYPE + " challenge, don't know what to do...");
        }

        // Output the challenge, wait for acknowledge...
        Tr.info(tc, "Please create a file in your web server's base directory.");
        Tr.info(tc, "It must be reachable at: http://" + auth.getDomain() + "/.well-known/acme-challenge/" + challenge.getToken());
        Tr.info(tc, "File name: " + challenge.getToken());
        Tr.info(tc, "Content: " + challenge.getAuthorization());
        Tr.info(tc, "The file must not contain any leading or trailing whitespaces or line breaks!");
        Tr.info(tc, "If you're ready, dismiss the dialog...");

        StringBuilder message = new StringBuilder();
        // message.append("Please create a file in your web server's base directory.\n\n");
        // message.append("http://").append(auth.getDomain()).append("/.well-known/acme-challenge/").append(challenge.getToken()).append("\n\n");
        // message.append("Content:\n\n");
		        
        String current = new java.io.File( "." ).getCanonicalPath();
        Tr.info(tc, "***JTM*** Current dir:"+current);
        Tr.info(tc, "***JTM*** Create new file name: "+current+"/"+challenge.getToken());
        Tr.info(tc, "***JTM*** With contents: "+challenge.getAuthorization());
        String data = challenge.getAuthorization();
        FileOutputStream out = new FileOutputStream(current+"/"+challenge.getToken());
        out.write(data.getBytes());
        out.close();
        
        // message.append(challenge.getAuthorization());
        // acceptChallenge(message.toString());

        return challenge;
    }

    /**
     * Prepares a DNS challenge.
     * <p>
     * The verification of this challenge expects a TXT record with a certain content.
     * <p>
     * This example outputs instructions that need to be executed manually. In a
     * production environment, you would rather configure your DNS automatically.
     *
     * @param auth
     *            {@link Authorization} to find the challenge in
     * @return {@link Challenge} to verify
     */
    public Challenge dnsChallenge(Authorization auth) throws AcmeException {
        // Find a single dns-01 challenge
        Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE);
        if (challenge == null) {
            throw new AcmeException("Found no " + Dns01Challenge.TYPE + " challenge, don't know what to do...");
        }

        // Output the challenge, wait for acknowledge...
        Tr.info(tc, "Please create a TXT record:");
        Tr.info(tc, "_acme-challenge." + auth.getDomain() + ". IN TXT " + challenge.getDigest());
        Tr.info(tc, "If you're ready, dismiss the dialog...");

        StringBuilder message = new StringBuilder();
        message.append("Please create a TXT record:\n\n");
        message.append("_acme-challenge." + auth.getDomain() + ". IN TXT " + challenge.getDigest());
        // acceptChallenge(message.toString());

        return challenge;
    }

    
 	private final ConcurrentServiceReferenceMap<String, AcmeAuthorizationServices> acmeAuthServiceRef = 
			new ConcurrentServiceReferenceMap<String, AcmeAuthorizationServices>("acmeAuthService");
    
    @Reference(service = AcmeAuthorizationServices.class, name = "com.ibm.ws.acme.web.AcmeAuthorizationServices", policy = ReferencePolicy.DYNAMIC, 
    		cardinality = ReferenceCardinality.MULTIPLE, policyOption = ReferencePolicyOption.GREEDY)
	
    protected void setAcmeAuthService(ServiceReference<AcmeAuthorizationServices> ref) {
		synchronized (acmeAuthServiceRef) {
			Tr.info(tc, "AcmeProviderImpl: setAcmeAuth() Setting reference for " + ref.getProperty("acmeAuthID"));
			acmeAuthServiceRef.putReference((String) ref.getProperty("acmeAuthID"), ref);
		}
	}

	protected void unsetAcmeAuthService(ServiceReference<AcmeAuthorizationServices> ref) {
		synchronized (acmeAuthServiceRef) {
			Tr.info(tc, "AcmeProviderImpl: unsetAcmeAuth() Unsetting reference for " + ref.getProperty("acmeAuthID"));
			acmeAuthServiceRef.removeReference((String) ref.getProperty("acmeAuthID"), ref);
		}
	}


}

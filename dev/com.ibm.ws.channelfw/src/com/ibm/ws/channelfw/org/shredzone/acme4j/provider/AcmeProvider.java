/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2015 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package com.ibm.ws.channelfw.org.shredzone.acme4j.provider;

import java.net.URI;
import java.net.URL;
import java.util.ServiceLoader;

import javax.annotation.CheckForNull;
import javax.annotation.ParametersAreNonnullByDefault;

import com.ibm.ws.channelfw.org.shredzone.acme4j.Login;
import com.ibm.ws.channelfw.org.shredzone.acme4j.Session;
import com.ibm.ws.channelfw.org.shredzone.acme4j.challenge.Challenge;
import com.ibm.ws.channelfw.org.shredzone.acme4j.connector.Connection;
import com.ibm.ws.channelfw.org.shredzone.acme4j.exception.AcmeException;
import com.ibm.ws.channelfw.org.shredzone.acme4j.toolbox.JSON;

/**
 * An {@link AcmeProvider} provides methods to be used for communicating with the ACME
 * server. Implementations handle individual features of each ACME server.
 * <p>
 * Provider implementations must be registered with Java's {@link ServiceLoader}.
 */
@ParametersAreNonnullByDefault
public interface AcmeProvider {

    /**
     * Checks if this provider accepts the given server URI.
     *
     * @param serverUri
     *            Server URI to test
     * @return {@code true} if this provider accepts the server URI, {@code false}
     *         otherwise
     */
    boolean accepts(URI serverUri);

    /**
     * Resolves the server URI and returns the matching directory URL.
     *
     * @param serverUri
     *            Server {@link URI}
     * @return Resolved directory {@link URL}
     * @throws IllegalArgumentException
     *             if the server {@link URI} is not accepted
     */
    URL resolve(URI serverUri);

    /**
     * Creates a {@link Connection} for communication with the ACME server.
     *
     * @return {@link Connection} that was generated
     */
    Connection connect();

    /**
     * Returns the provider's directory. The structure must contain resource URLs, and may
     * optionally contain metadata.
     * <p>
     * The default implementation resolves the server URI and fetches the directory via
     * HTTP request. Subclasses may override this method, e.g. if the directory is static.
     *
     * @param session
     *            {@link Session} to be used
     * @param serverUri
     *            Server {@link URI}
     * @return Directory data, as JSON object
     */
    JSON directory(Session session, URI serverUri) throws AcmeException;

    /**
     * Creates a {@link Challenge} instance for the given challenge data.
     *
     * @param login
     *            {@link Login} to bind the challenge to
     * @param data
     *            Challenge {@link JSON} data
     * @return {@link Challenge} instance, or {@code null} if this provider is unable to
     *         generate a matching {@link Challenge} instance.
     */
    @CheckForNull
    Challenge createChallenge(Login login, JSON data);

}

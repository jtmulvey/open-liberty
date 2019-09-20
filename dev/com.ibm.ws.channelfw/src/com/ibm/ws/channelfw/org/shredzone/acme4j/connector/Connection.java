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
package com.ibm.ws.channelfw.org.shredzone.acme4j.connector;

import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import javax.annotation.CheckForNull;
import javax.annotation.ParametersAreNonnullByDefault;

import com.ibm.ws.channelfw.org.shredzone.acme4j.Login;
import com.ibm.ws.channelfw.org.shredzone.acme4j.Session;
import com.ibm.ws.channelfw.org.shredzone.acme4j.exception.AcmeException;
import com.ibm.ws.channelfw.org.shredzone.acme4j.exception.AcmeRetryAfterException;
import com.ibm.ws.channelfw.org.shredzone.acme4j.toolbox.JSON;
import com.ibm.ws.channelfw.org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * Connects to the ACME server and offers different methods for invoking the API.
 */
@ParametersAreNonnullByDefault
public interface Connection extends AutoCloseable {

    /**
     * Resets the session nonce, by fetching a new one.
     *
     * @param session
     *            {@link Session} instance to fetch a nonce for
     */
    void resetNonce(Session session) throws AcmeException;

    /**
     * Sends a simple GET request.
     * <p>
     * If the response code was not {@link HttpURLConnection#HTTP_OK}, an
     * {@link AcmeException} matching the error is raised.
     *
     * @param url
     *            {@link URL} to send the request to.
     * @param session
     *            {@link Session} instance to be used for tracking
     */
    void sendRequest(URL url, Session session) throws AcmeException;

    /**
     * Sends a signed POST request. Requires a {@link Login} for the session and
     * {@link KeyPair}. The {@link Login} account location is sent in a "kid" protected
     * header.
     * <p>
     * If the server does not return a 200 class status code, an {@link AcmeException} is
     * raised matching the error.
     *
     * @param url
     *            {@link URL} to send the request to.
     * @param claims
     *            {@link JSONBuilder} containing claims.
     * @param login
     *            {@link Login} instance to be used for signing and tracking.
     * @return HTTP 200 class status that was returned
     */
    int sendSignedRequest(URL url, JSONBuilder claims, Login login) throws AcmeException;

    /**
     * Sends a signed POST request. Only requires a {@link Session}. The {@link KeyPair}
     * is sent in a "jwk" protected header field.
     * <p>
     * If the server does not return a 200 class status code, an {@link AcmeException} is
     * raised matching the error.
     *
     * @param url
     *            {@link URL} to send the request to.
     * @param claims
     *            {@link JSONBuilder} containing claims.
     * @param session
     *            {@link Session} instance to be used for tracking.
     * @param keypair
     *            {@link KeyPair} to be used for signing.
     * @return HTTP 200 class status that was returned
     */
    int sendSignedRequest(URL url, JSONBuilder claims, Session session, KeyPair keypair)
                throws AcmeException;

    /**
     * Reads a server response as JSON data.
     *
     * @return The JSON response, or {@code null} if the server did not provide any data.
     */
    @CheckForNull
    JSON readJsonResponse() throws AcmeException;

    /**
     * Reads a certificate and its issuers.
     *
     * @return List of X.509 certificate and chain that was read.
     */
    List<X509Certificate> readCertificates() throws AcmeException;

    /**
     * Throws an {@link AcmeRetryAfterException} if the last status was HTTP Accepted and
     * a Retry-After header was received.
     *
     * @param message
     *            Message to be sent along with the {@link AcmeRetryAfterException}
     */
    void handleRetryAfter(String message) throws AcmeException;

    /**
     * Gets the nonce from the nonce header.
     *
     * @return Base64 encoded nonce, or {@code null} if no nonce header was set
     */
    @CheckForNull
    String getNonce();

    /**
     * Gets a location from the {@code Location} header.
     * <p>
     * Relative links are resolved against the last request's URL.
     *
     * @return Location {@link URL}, or {@code null} if no Location header was set
     */
    @CheckForNull
    URL getLocation();

    /**
     * Gets one or more relation links from the header. The result is expected to be an URL.
     * <p>
     * Relative links are resolved against the last request's URL.
     *
     * @param relation
     *            Link relation
     * @return Collection of links. Empty if there was no such relation.
     */
    Collection<URL> getLinks(String relation);

    /**
     * Closes the {@link Connection}, releasing all resources.
     */
    @Override
    void close();

}

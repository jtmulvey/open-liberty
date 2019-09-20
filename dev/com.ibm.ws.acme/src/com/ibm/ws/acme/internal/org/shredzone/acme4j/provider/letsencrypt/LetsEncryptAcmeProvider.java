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
package com.ibm.ws.acme.internal.org.shredzone.acme4j.provider.letsencrypt;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import javax.annotation.ParametersAreNonnullByDefault;

import com.ibm.ws.acme.internal.org.shredzone.acme4j.exception.AcmeProtocolException;
import com.ibm.ws.acme.internal.org.shredzone.acme4j.provider.AbstractAcmeProvider;
import com.ibm.ws.acme.internal.org.shredzone.acme4j.provider.AcmeProvider;

/**
 * An {@link AcmeProvider} for <em>Let's Encrypt</em>.
 * <p>
 * The {@code serverUri} is {@code "acme://letsencrypt.org"} for the production server,
 * and {@code "acme://letsencrypt.org/staging"} for a testing server.
 * <p>
 * If you want to use <em>Let's Encrypt</em>, always prefer to use this provider.
 *
 * @see <a href="https://letsencrypt.org/">Let's Encrypt</a>
 */
@ParametersAreNonnullByDefault
public class LetsEncryptAcmeProvider extends AbstractAcmeProvider {

    private static final String V02_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory";
    private static final String STAGING_DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory";

    @Override
    public boolean accepts(URI serverUri) {
        return "acme".equals(serverUri.getScheme())
                && "letsencrypt.org".equals(serverUri.getHost());
    }

    @Override
    public URL resolve(URI serverUri) {
    	
    	System.out.println("*** JTM **** Entered LetsEncryptAcmeProvider resolve method!");
    	
        String path = serverUri.getPath();
        String directoryUrl;
        if (path == null || "".equals(path) || "/".equals(path) || "/v02".equals(path)) {
            directoryUrl = V02_DIRECTORY_URL;
        } else if ("/staging".equals(path)) {
            directoryUrl = STAGING_DIRECTORY_URL;
        } else {
            throw new IllegalArgumentException("Unknown URI " + serverUri);
        }
    	System.out.println("*** JTM **** LetsEncryptAcmeProvider directoryUrl: "+ directoryUrl.toString());

        try {
            return new URL(directoryUrl);
        } catch (MalformedURLException ex) {
            throw new AcmeProtocolException(directoryUrl, ex);
        }
    }

}

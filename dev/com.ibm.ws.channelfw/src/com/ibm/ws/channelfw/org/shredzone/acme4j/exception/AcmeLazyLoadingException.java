/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2016 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package com.ibm.ws.channelfw.org.shredzone.acme4j.exception;

import static java.util.Objects.requireNonNull;

import java.net.URL;

import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

import com.ibm.ws.channelfw.org.shredzone.acme4j.AcmeResource;

/**
 * This runtime exception is thrown when an {@link AcmeException} occured while trying to
 * lazy-load a resource from the ACME server.
 */
@ParametersAreNonnullByDefault
@Immutable
public class AcmeLazyLoadingException extends RuntimeException {
    private static final long serialVersionUID = 1000353433913721901L;

    private final Class<? extends AcmeResource> type;
    private final URL location;

    /**
     * Creates a new {@link AcmeLazyLoadingException}.
     *
     * @param resource
     *            {@link AcmeResource} to be loaded
     * @param cause
     *            {@link AcmeException} that was raised
     */
    public AcmeLazyLoadingException(AcmeResource resource, AcmeException cause) {
        super(requireNonNull(resource).getClass().getSimpleName() + " "
            + requireNonNull(resource).getLocation(), requireNonNull(cause));
        type = resource.getClass();
        location = resource.getLocation();
    }

    /**
     * Returns the {@link AcmeResource} type of the resource that could not be loaded.
     */
    public Class<? extends AcmeResource> getType() {
        return type;
    }

    /**
     * Returns the location of the resource that could not be loaded.
     */
    public URL getLocation() {
        return location;
    }

}

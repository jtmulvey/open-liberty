/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2018 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package com.ibm.ws.channelfw.org.shredzone.acme4j;

import java.net.URL;
import java.util.Objects;

import javax.annotation.ParametersAreNonnullByDefault;

import com.ibm.ws.channelfw.org.shredzone.acme4j.connector.Connection;
import com.ibm.ws.channelfw.org.shredzone.acme4j.exception.AcmeException;
import com.ibm.ws.channelfw.org.shredzone.acme4j.exception.AcmeLazyLoadingException;
import com.ibm.ws.channelfw.org.shredzone.acme4j.exception.AcmeRetryAfterException;
import com.ibm.ws.channelfw.org.shredzone.acme4j.toolbox.JSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An ACME resource that stores its state in a JSON structure.
 */
@ParametersAreNonnullByDefault
public abstract class AcmeJsonResource extends AcmeResource {
    private static final long serialVersionUID = -5060364275766082345L;
    private static final Logger LOG = LoggerFactory.getLogger(AcmeJsonResource.class);

    private JSON data = null;

    /**
     * Create a new {@link AcmeJsonResource}.
     *
     * @param login
     *            {@link Login} the resource is bound with
     * @param location
     *            Location {@link URL} of this resource
     */
    protected AcmeJsonResource(Login login, URL location) {
        super(login, location);
    }

    /**
     * Returns the JSON representation of the resource data.
     * <p>
     * If there is no data, {@link #update()} is invoked to fetch it from the server.
     * <p>
     * This method can be used to read proprietary data from the resources.
     *
     * @return Resource data, as {@link JSON}.
     */
    public JSON getJSON() {
        if (data == null) {
            try {
                update();
            } catch (AcmeRetryAfterException ex) {
                // ignore... The object was still updated.
                System.out.println("Retry-After " + ex);
            } catch (AcmeException ex) {
                throw new AcmeLazyLoadingException(this, ex);
            }
        }
        return data;
    }

    /**
     * Sets the JSON representation of the resource data.
     *
     * @param data
     *            New {@link JSON} data, must not be {@code null}.
     */
    protected void setJSON(JSON data) {
        this.data = Objects.requireNonNull(data, "data");
    }

    /**
     * Checks if this resource is valid.
     *
     * @return {@code true} if the resource state has been loaded from the server. If
     *         {@code false}, {@link #getJSON()} would implicitly call {@link #update()}
     *         to fetch the current state from the server.
     */
    protected boolean isValid() {
        return data != null;
    }

    /**
     * Invalidates the state of this resource. Enforces an {@link #update()} when
     * {@link #getJSON()} is invoked.
     */
    protected void invalidate() {
        data = null;
    }

    /**
     * Updates this resource, by fetching the current resource data from the server.
     *
     * @throws AcmeException
     *             if the resource could not be fetched.
     * @throws AcmeRetryAfterException
     *             the resource is still being processed, and the server returned an
     *             estimated date when the process will be completed. If you are polling
     *             for the resource to complete, you should wait for the date given in
     *             {@link AcmeRetryAfterException#getRetryAfter()}. Note that the status
     *             of the resource is updated even if this exception was thrown.
     */
    public void update() throws AcmeException {
        String resourceType = getClass().getSimpleName();
        System.out.println("update {} "+ resourceType);
        try (Connection conn = connect()) {
            conn.sendRequest(getLocation(), getSession());
            JSON json = conn.readJsonResponse();
            if (json != null) {
                setJSON(json);
            }
            conn.handleRetryAfter(resourceType + " is not completed yet");
        }
    }

}

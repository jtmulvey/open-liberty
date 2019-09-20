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

import java.time.Instant;
import java.util.Objects;

import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

/**
 * This exception is thrown when a server side process has not been completed yet, and the
 * server returned an estimated retry date.
 */
@ParametersAreNonnullByDefault
@Immutable
public class AcmeRetryAfterException extends AcmeException {
    private static final long serialVersionUID = 4461979121063649905L;

    private final Instant retryAfter;

    /**
     * Creates a new {@link AcmeRetryAfterException}.
     *
     * @param msg
     *            Error details
     * @param retryAfter
     *            retry-after date returned by the server
     */
    public AcmeRetryAfterException(String msg, Instant retryAfter) {
        super(msg);
        this.retryAfter = Objects.requireNonNull(retryAfter);
    }

    /**
     * Returns the retry-after date returned by the server.
     */
    public Instant getRetryAfter() {
        return retryAfter;
    }

}

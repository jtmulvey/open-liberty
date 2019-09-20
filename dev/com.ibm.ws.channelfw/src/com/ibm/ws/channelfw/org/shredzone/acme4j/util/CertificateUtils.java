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
package com.ibm.ws.channelfw.org.shredzone.acme4j.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;

import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.WillClose;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import com.ibm.ws.channelfw.org.shredzone.acme4j.challenge.TlsAlpn01Challenge;

/**
 * Utility class offering convenience methods for certificates.
 * <p>
 * Requires {@code Bouncy Castle}. This class is part of the {@code acme4j-utils} module.
 */
@ParametersAreNonnullByDefault
public final class CertificateUtils {

    /**
     * The {@code acmeValidation-v1} object identifier.
     *
     * @since 2.1
     */
    public static final ASN1ObjectIdentifier ACME_VALIDATION_V1 =
                    new ASN1ObjectIdentifier(TlsAlpn01Challenge.ACME_VALIDATION_V1_OID).intern();

    private CertificateUtils() {
        // utility class without constructor
    }

    /**
     * Reads a CSR PEM file.
     *
     * @param in
     *            {@link InputStream} to read the CSR from. The {@link InputStream} is
     *            closed after use.
     * @return CSR that was read
     */
    public static PKCS10CertificationRequest readCSR(@WillClose InputStream in) throws IOException {
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(in, StandardCharsets.US_ASCII))) {
            Object parsedObj = pemParser.readObject();
            if (!(parsedObj instanceof PKCS10CertificationRequest)) {
                throw new IOException("Not a PKCS10 CSR");
            }
            return (PKCS10CertificationRequest) parsedObj;
        }
    }

    /**
     * Creates a self-signed {@link X509Certificate} that can be used for the
     * {@link TlsAlpn01Challenge}. The certificate is valid for 7 days.
     *
     * @param keypair
     *            A domain {@link KeyPair} to be used for the challenge
     * @param subject
     *            The subject (domain name) that is to be validated
     * @param acmeValidationV1
     *            The value that is returned by
     *            {@link TlsAlpn01Challenge#getAcmeValidationV1()}
     * @return Created certificate
     * @since 2.1
     */
    public static X509Certificate createTlsAlpn01Certificate(KeyPair keypair, String subject, byte[] acmeValidationV1)
                throws IOException {
        Objects.requireNonNull(keypair, "keypair");
        Objects.requireNonNull(subject, "subject");
        if (acmeValidationV1 == null || acmeValidationV1.length != 32) {
            throw new IllegalArgumentException("Bad acmeValidationV1 parameter");
        }

        final long now = System.currentTimeMillis();
        final String signatureAlg = "SHA256withRSA";

        try {
            X500Name issuer = new X500Name("CN=acme.invalid");
            BigInteger serial = BigInteger.valueOf(now);
            Instant notBefore = Instant.ofEpochMilli(now);
            Instant notAfter = notBefore.plus(Duration.ofDays(7));

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                        issuer, serial, Date.from(notBefore), Date.from(notAfter),
                        issuer, keypair.getPublic());

            GeneralName[] gns = new GeneralName[1];
            gns[0] = new GeneralName(GeneralName.dNSName, subject);
            certBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(gns));

            certBuilder.addExtension(ACME_VALIDATION_V1, true, new DEROctetString(acmeValidationV1));

            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlg);

            byte[] cert = certBuilder.build(signerBuilder.build(keypair.getPrivate())).getEncoded();

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(cert));
        } catch (CertificateException | OperatorCreationException ex) {
            throw new IOException(ex);
        }
    }

}

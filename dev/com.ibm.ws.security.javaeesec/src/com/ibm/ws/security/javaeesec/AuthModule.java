/*******************************************************************************
 * Copyright (c) 2017 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.javaeesec;

import java.util.HashMap;
import java.util.Map;

import javax.enterprise.inject.Instance;
import javax.enterprise.inject.spi.CDI;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.MessagePolicy.ProtectionPolicy;
import javax.security.auth.message.MessagePolicy.TargetPolicy;
import javax.security.auth.message.module.ServerAuthModule;
import javax.security.enterprise.AuthenticationException;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.AuthenticationParameters;
import javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Trivial;
import com.ibm.ws.security.javaeesec.authentication.mechanism.http.HAMProperties;

/*
 * This JASPI authentication module is used as the bridge ServerAuthModule for JSR-375.
 */
public class AuthModule implements ServerAuthModule {

    private static final TraceComponent tc = Tr.register(AuthModule.class);

    private static Class[] supportedMessageTypes = new Class[] { HttpServletRequest.class, HttpServletResponse.class };

    private MessagePolicy requestPolicy;
    private CallbackHandler handler;
    private Map<String, String> options;

    @Override
    public Class[] getSupportedMessageTypes() {
        return supportedMessageTypes;
    }

    @Override
    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, Map options) throws AuthException {
        this.requestPolicy = requestPolicy;
        this.handler = handler;
        this.options = new HashMap<String, String>();
        if (options != null) {
            this.options.putAll(options);
        }

        if (tc.isDebugEnabled()) {
            if (requestPolicy != null && requestPolicy.getTargetPolicies() != null) {
                for (TargetPolicy target : requestPolicy.getTargetPolicies()) {
                    ProtectionPolicy protectionPolicy = target.getProtectionPolicy();

                    if (protectionPolicy != null) {
                        Tr.debug(tc, "Target request ProtectionPolicy=" + protectionPolicy.getID());
                    }
                }
            }
        }

    }

    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
        AuthStatus status = AuthStatus.SEND_FAILURE;

        try {
            HttpAuthenticationMechanism authMech = getHttpAuthenticationMechanism();
            HttpMessageContext httpMessageContext = createHttpMessageContext(messageInfo, clientSubject);
            AuthenticationStatus authenticationStatus = authMech.validateRequest((HttpServletRequest) messageInfo.getRequestMessage(),
                                                                                 (HttpServletResponse) messageInfo.getResponseMessage(),
                                                                                 httpMessageContext);
            status = translateValidateRequestStatus(authenticationStatus);
            registerSession(httpMessageContext);
        } catch (AuthException ae) {
            throw ae;
        } catch (Exception e) {
            // TODO: Issue serviceability message.
            e.printStackTrace();
            AuthException authException = new AuthException();
            authException.initCause(e);
            throw authException;
        }
        return status;
    }

    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
        AuthStatus status = AuthStatus.SEND_FAILURE;
        // TODO: Determine if HttpMessageContext and HttpAuthenticationMechanism must have been cached in the MessageInfo
        try {
            HttpAuthenticationMechanism authMech = getHttpAuthenticationMechanism();
            HttpMessageContext httpMessageContext = createHttpMessageContext(messageInfo, null);
            AuthenticationStatus authenticationStatus = authMech.secureResponse((HttpServletRequest) messageInfo.getRequestMessage(),
                                                                                (HttpServletResponse) messageInfo.getResponseMessage(),
                                                                                httpMessageContext);
            status = translateSecureResponseStatus(authenticationStatus);
        } catch (AuthException ae) {
            throw ae;
        } catch (AuthenticationException e) {
            // TODO: Issue serviceability message.
            e.printStackTrace();
            AuthException authException = new AuthException();
            authException.initCause(e);
            throw authException;
        }
        return status;
    }

    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
        HttpAuthenticationMechanism authMech = getHttpAuthenticationMechanism();
        HttpMessageContext httpMessageContext = createHttpMessageContext(messageInfo, null);
        authMech.cleanSubject((HttpServletRequest) messageInfo.getRequestMessage(), (HttpServletResponse) messageInfo.getResponseMessage(), httpMessageContext);
    }

    private HttpAuthenticationMechanism getHttpAuthenticationMechanism() throws AuthException {
        Instance<HAMProperties> hampInstance = getCDI().select(HAMProperties.class);
        if (hampInstance != null && !hampInstance.isUnsatisfied() && !hampInstance.isAmbiguous()) {
            Instance<HttpAuthenticationMechanism> beanInstance = getCDI().select(hampInstance.get().getImplementationClass());
            if (beanInstance != null && !beanInstance.isUnsatisfied() && !beanInstance.isAmbiguous()) {
                return beanInstance.get();
            } else {
                String msg = Tr.formatMessage(tc, "JAVAEESEC_ERROR_NO_HAM");
                throw new AuthException(msg);
            }
        } else {
            String msg = Tr.formatMessage(tc, "JAVAEESEC_ERROR_NO_HAM_PROPS");
            throw new AuthException(msg);
        }
    }

    protected CDI getCDI() {
        return CDI.current();
    }

    protected HttpMessageContext createHttpMessageContext(MessageInfo messageInfo, Subject clientSubject) {
        HttpMessageContextImpl httpMessageContext = null;
        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
        AuthenticationParameters authParams = (AuthenticationParameters) request.getAttribute(JavaEESecConstants.SECURITY_CONTEXT_AUTH_PARAMS);
        if (authParams != null) {
            request.removeAttribute(JavaEESecConstants.SECURITY_CONTEXT_AUTH_PARAMS);
            httpMessageContext = new HttpMessageContextImpl(messageInfo, clientSubject, handler, authParams);
        } else {
            httpMessageContext = new HttpMessageContextImpl(messageInfo, clientSubject, handler);
        }
        return httpMessageContext;
    }

    private AuthStatus translateValidateRequestStatus(AuthenticationStatus authenticationStatus) {
        AuthStatus status = AuthStatus.SEND_FAILURE;
        if (AuthenticationStatus.SUCCESS.equals(authenticationStatus)) {
            status = AuthStatus.SUCCESS;
        } else {
            status = translateCommon(authenticationStatus);
        }
        return status;
    }

    @SuppressWarnings("unchecked")
    private void registerSession(HttpMessageContext httpMessageContext) {
        if (httpMessageContext.isRegisterSession()) {
            httpMessageContext.getMessageInfo().getMap().put("javax.servlet.http.registerSession", Boolean.TRUE.toString());
        }
    }

    private AuthStatus translateSecureResponseStatus(AuthenticationStatus authenticationStatus) {
        AuthStatus status = AuthStatus.SEND_FAILURE;
        if (AuthenticationStatus.SUCCESS.equals(authenticationStatus)) {
            status = AuthStatus.SEND_SUCCESS;
        } else {
            status = translateCommon(authenticationStatus);
        }
        return status;
    }

    @Trivial
    private AuthStatus translateCommon(AuthenticationStatus authenticationStatus) {
        AuthStatus status = AuthStatus.SEND_FAILURE;
        if (AuthenticationStatus.SEND_FAILURE.equals(authenticationStatus)) {
            status = AuthStatus.SEND_FAILURE;
        } else if (AuthenticationStatus.SEND_CONTINUE.equals(authenticationStatus)) {
            status = AuthStatus.SEND_CONTINUE;
        } else if (AuthenticationStatus.NOT_DONE.equals(authenticationStatus)) {
            status = AuthStatus.SUCCESS;
        }
        return status;
    }
}

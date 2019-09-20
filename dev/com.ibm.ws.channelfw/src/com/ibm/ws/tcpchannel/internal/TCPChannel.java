/*******************************************************************************
 * Copyright (c) 2005, 2006 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.tcpchannel.internal;

import java.io.File;
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

import java.io.IOException;
import java.net.Inet6Address;
import java.net.Socket;
import java.nio.channels.SocketChannel;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Queue;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import com.ibm.websphere.channelfw.ChannelData;
import com.ibm.websphere.channelfw.osgi.CHFWBundle;
import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.ws.ffdc.FFDCFilter;
import com.ibm.ws.ffdc.FFDCSelfIntrospectable;
import com.ibm.ws.staticvalue.StaticValue;
import com.ibm.wsspi.bytebuffer.WsByteBuffer;
import com.ibm.wsspi.channelfw.ChannelFrameworkFactory;
import com.ibm.wsspi.channelfw.ConnectionLink;
import com.ibm.wsspi.channelfw.DiscriminationProcess;
import com.ibm.wsspi.channelfw.Discriminator;
import com.ibm.wsspi.channelfw.InboundChannel;
import com.ibm.wsspi.channelfw.OutboundChannel;
import com.ibm.wsspi.channelfw.VirtualConnection;
import com.ibm.wsspi.channelfw.VirtualConnectionFactory;
import com.ibm.wsspi.channelfw.exception.ChannelException;
import com.ibm.wsspi.channelfw.exception.RetryableChannelException;
import com.ibm.wsspi.connmgmt.ConnectionHandle;
import com.ibm.wsspi.connmgmt.ConnectionType;
import com.ibm.wsspi.tcpchannel.TCPConfigConstants;
import com.ibm.wsspi.tcpchannel.TCPConnectRequestContext;
import com.ibm.wsspi.tcpchannel.TCPConnectionContext;

import com.ibm.ws.channelfw.org.shredzone.acme4j.*;
import com.ibm.ws.channelfw.org.shredzone.acme4j.Certificate.*;
import com.ibm.ws.channelfw.org.shredzone.acme4j.Order.*;
import com.ibm.ws.channelfw.org.shredzone.acme4j.challenge.*;
import com.ibm.ws.channelfw.org.shredzone.acme4j.connector.*;
import com.ibm.ws.channelfw.org.shredzone.acme4j.exception.*;
import com.ibm.ws.channelfw.org.shredzone.acme4j.provider.*;
import com.ibm.ws.channelfw.org.shredzone.acme4j.util.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;



/**
 * Basic TCP channel class.
 */
@SuppressWarnings("unchecked")
public abstract class TCPChannel implements InboundChannel, OutboundChannel, FFDCSelfIntrospectable {

    volatile protected static StaticValue<NBAccept> acceptReqProcessor = StaticValue.createStaticValue(null);

    private String channelName = null;
    protected String externalName = null;
    private ChannelData channelData;
    protected TCPChannelConfiguration config;
    protected ConnectionManager connectionManager = null;
    protected VirtualConnectionFactory vcFactory = null;
    private TCPPort endPoint = null;
    private DiscriminationProcess discriminationProcess = null;
    private long lastConnExceededTime = 0;
    private AccessLists alists;

    private final static int SIZE_IN_USE = 128;
    private final Queue<TCPConnLink>[] inUse = new ConcurrentLinkedQueue[SIZE_IN_USE];
    private final AtomicInteger inUseIndex = new AtomicInteger(SIZE_IN_USE);

    protected volatile boolean stopFlag = true;
    private boolean preparingToStop = false;
    private String displayableHostName = null;

    private static final TraceComponent tc = Tr.register(TCPChannel.class, TCPChannelMessageConstants.TCP_TRACE_NAME, TCPChannelMessageConstants.TCP_BUNDLE);

    protected TCPChannelFactory channelFactory = null;

    private int connectionCount = 0; // inbound connection count
    private final Object connectionCountSync = new Object() {}; // sync object for above counter

    protected StatisticsLogger statLogger = null;
    protected final AtomicLong totalSyncReads = new AtomicLong(0);
    protected final AtomicLong totalAsyncReads = new AtomicLong(0);
    protected final AtomicLong totalAsyncReadRetries = new AtomicLong(0);
    protected final AtomicLong totalPartialAsyncReads = new AtomicLong(0);
    protected final AtomicLong totalPartialSyncReads = new AtomicLong(0);
    protected final AtomicLong totalSyncWrites = new AtomicLong(0);
    protected final AtomicLong totalAsyncWrites = new AtomicLong(0);
    protected final AtomicLong totalAsyncWriteRetries = new AtomicLong(0);
    protected final AtomicLong totalPartialAsyncWrites = new AtomicLong(0);
    protected final AtomicLong totalPartialSyncWrites = new AtomicLong(0);
    protected final AtomicLong totalConnections = new AtomicLong(0);
    protected final AtomicLong maxConcurrentConnections = new AtomicLong(0);
    
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


    /**
     * Constructor.
     */
    public TCPChannel() {
        // nothing to do here
    }

    /**
     * Initialize this channel.
     *
     * @param runtimeConfig
     * @param tcpConfig
     * @throws ChannelException
     */
    public void setup(ChannelData runtimeConfig, TCPChannelConfiguration tcpConfig) throws ChannelException {
        setup(runtimeConfig, tcpConfig, null);
    }

    /**
     * Initialize this channel.
     *
     * @param runtimeConfig
     * @param tcpConfig
     * @param factory
     * @return ChannelTermination
     * @throws ChannelException
     */
    public ChannelTermination setup(ChannelData runtimeConfig, TCPChannelConfiguration tcpConfig, TCPChannelFactory factory) throws ChannelException {
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.entry(tc, "setup");
        }
        this.channelFactory = factory;
        this.channelData = runtimeConfig;
        this.channelName = runtimeConfig.getName();
        this.externalName = runtimeConfig.getExternalName();
        this.config = tcpConfig;

        for (int i = 0; i < this.inUse.length; i++) {
            this.inUse[i] = new ConcurrentLinkedQueue<TCPConnLink>();
        }

        this.vcFactory = ChannelFrameworkFactory.getChannelFramework().getInboundVCFactory();

        this.alists = AccessLists.getInstance(this.config);

        if (this.config.isInbound() && acceptReqProcessor.get() == null) {
            acceptReqProcessor = StaticValue.mutateStaticValue(acceptReqProcessor, new Callable<NBAccept>() {
                @Override
                public NBAccept call() throws Exception {
                    return new NBAccept(TCPChannel.this.config);
                }

            });
        }

        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.exit(tc, "setup");
        }
        return null;
    }

    protected AccessLists getAccessLists() {
        return this.alists;
    }

    protected boolean getStopFlag() {
        return this.stopFlag;
    }

    protected String getDisplayableHostName() {
        return this.displayableHostName;
    }

    protected void decrementConnectionCount() {
        synchronized (this.connectionCountSync) {
            this.connectionCount--;
        }
    }

    protected void incrementConnectionCount() {
        synchronized (this.connectionCountSync) {
            this.connectionCount++;
        }
        if (getConfig().getDumpStatsInterval() > 0) {
            this.totalConnections.incrementAndGet();
            long oldMax = this.maxConcurrentConnections.get();
            while (this.connectionCount > oldMax) {
                this.maxConcurrentConnections.compareAndSet(oldMax, this.connectionCount);
                oldMax = this.maxConcurrentConnections.get();
            }
        }
    }

    protected int getInboundConnectionCount() {
        return this.connectionCount;
    }

    /*
     * @see com.ibm.wsspi.channelfw.InboundChannel#getDiscriminatoryType()
     */
    @Override
    public Class<?> getDiscriminatoryType() {
        return WsByteBuffer.class;
    }

    /**
     * Access the configuration for the channel.
     *
     * @return TCPChannelConfiguration
     */
    public TCPChannelConfiguration getConfig() {
        return this.config;
    }

    protected ConnectionManager getConnMgr() {
        return this.connectionManager;
    }

    /*
     * @see com.ibm.wsspi.channelfw.Channel#getConnectionLink(VirtualConnection)
     */
    @Override
    public ConnectionLink getConnectionLink(VirtualConnection vc) {
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.entry(tc, "getConnectionLink");
        }

        // add this new connection link to the next in-use list based on
        // the atomic index, the extra add/mod handles the negative values
        int index = ((this.inUseIndex.getAndIncrement() % SIZE_IN_USE) + SIZE_IN_USE) % SIZE_IN_USE;

        TCPConnLink connLink = new TCPConnLink(vc, this, this.config, index);
        this.inUse[index].add(connLink);

        // assign default ConnectionType and unique ConnectionHandle to new inbound
        // connection
        // ConnectionType may seem redundant, but is used on some platforms to
        // identify
        // more than just inbound/outbound flow.
        ConnectionType.setDefaultVCConnectionType(vc);
        ConnectionHandle.getConnectionHandle(vc);

        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.exit(tc, "getConnectionLink: " + connLink);
        }
        return connLink;
    }

    abstract protected TCPReadRequestContextImpl createReadInterface(TCPConnLink connLink);

    abstract protected TCPWriteRequestContextImpl createWriteInterface(TCPConnLink connLink);

    /*
     * @see com.ibm.wsspi.channelfw.Channel#start()
     */
    @Override
    public void start() throws ChannelException {
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.entry(tc, "start");
        }
        if (this.stopFlag) {
            // only start once
            this.stopFlag = false;
            if (this.config.isInbound()) {
                // Socket is already open, just need to start accepting connections
                try {
                    // PK60924 - check for a restart path requiring the re-init
                    if (null == this.endPoint.getServerSocket()) {
                        initializePort();
                    }
                    acceptReqProcessor.get().registerPort(this.endPoint);
                    this.preparingToStop = false;

                    String IPvType = "IPv4";
                    if (this.endPoint.getServerSocket().getInetAddress() instanceof Inet6Address) {
                        IPvType = "IPv6";
                    }

                    if (this.config.getHostname() == null) {
                        this.displayableHostName = "*  (" + IPvType + ")";
                    } else {
                        this.displayableHostName = this.endPoint.getServerSocket().getInetAddress().getHostName() + "  (" + IPvType + ": "
                                                   + this.endPoint.getServerSocket().getInetAddress().getHostAddress() + ")";
                    }
                    Tr.info(tc, TCPChannelMessageConstants.TCP_CHANNEL_STARTED,
                            new Object[] { getExternalName(), this.displayableHostName, String.valueOf(this.endPoint.getListenPort()) });

                    // Add code here to optionally drive LetsEncrypt
                    //if (this.endPoint.getListenPort() == 443) {
                    //    System.out.println("*** JTM *** Inside TCPChannel processed channel start on port 443!");;
                    //    Tr.info(tc, "JTM: call certificate factory - using LetsEncrypt!");
                        
                    //    Security.addProvider(new BouncyCastleProvider());
                        
                    //    Collection<String> domains = 
                    //    	    new ArrayList<String>(Arrays.asList(new String[] { "jmulvey.wascloud.net", "jmulvey.wascloud.net" }));

                    //    try {
                    //       fetchCertificate(domains);
                    //    }
                    //    catch (Exception ex) {
                    //      Tr.error(tc, "JTM: Failed to get a certificate for domains " + domains, ex);
                    //    }

                    //}

                } catch (IOException e) {
                    FFDCFilter.processException(e, getClass().getName() + ".start", "100", this);
                    if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                        Tr.event(tc, "TCP Channel: " + getExternalName() + "- Problem occurred while starting TCP Channel: " + e.getMessage());
                    }
                    ChannelException x = new ChannelException("TCP Channel: " + getExternalName() + "- Problem occurred while starting channel: " + e.getMessage());
                    // Adjust flag so follow up attempt is possible.
                    this.stopFlag = true;
                    throw x;
                }
            }
            if (this.config.getDumpStatsInterval() > 0) {
                createStatisticsThread();
            }
        }
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.exit(tc, "start");
        }
    }

    /*
     * @see com.ibm.wsspi.channelfw.Channel#init()
     */
    @Override
    public void init() throws ChannelException {
        if (this.config.isInbound()) {
            // Customize the TCPChannel configuration object so that it knows
            // what port to use for this chain.
            this.endPoint = createEndPoint();
            initializePort();
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, " listening port: " + this.endPoint.getListenPort());
            }
        }
    }

    /**
     * Initialize the endpoint listening socket.
     *
     * @throws ChannelException
     */
    private void initializePort() throws ChannelException {
        try {
            this.endPoint.initServerSocket();
        } catch (IOException ioe) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(tc, "TCP Channel: " + getExternalName() + "- Problem occurred while initializing TCP Channel: " + ioe.getMessage());
            }
            throw new ChannelException("TCP Channel: " + getExternalName() + "- Problem occurred while starting channel: " + ioe.getMessage());
        } catch (RetryableChannelException e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(tc, "TCP Channel: " + getExternalName() + "- Problem occurred while starting TCP Channel: " + e.getMessage());
            }
            throw e;
        }

        // add property to config to provide actual port used (could be ephemeral
        // port if '0' passed in)
        this.channelData.getPropertyBag().put(TCPConfigConstants.LISTENING_PORT, String.valueOf(this.endPoint.getListenPort()));
    }

    /**
     * Create the TCP end point for this channel.
     *
     * @return TCPPort
     * @throws ChannelException
     */
    public TCPPort createEndPoint() throws ChannelException {
        return new TCPPort(this, this.vcFactory);
    }

    /*
     * @see com.ibm.wsspi.channelfw.Channel#destroy()
     */
    @Override
    public void destroy() {
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Destroy " + getExternalName());
        }
        // Destroy the server socket
        if (this.endPoint != null) {
            this.endPoint.destroyServerSocket();
        }
        // disconnect from the factory
        if (null != this.channelFactory) {
            this.channelFactory.removeChannel(this.channelName);
        }
    }

    /*
     * @see com.ibm.wsspi.channelfw.InboundChannel#getDiscriminator()
     */
    @Override
    public Discriminator getDiscriminator() {
        if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
            Tr.event(tc, "getDiscriminator called erroneously on TCPChannel");
        }
        return null;
    }

    /*
     * @see com.ibm.wsspi.channelfw.Channel#stop(long)
     */
    @Override
    public void stop(long millisec) {
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.entry(tc, "stop (" + millisec + ") " + getExternalName());
        }
        // Stop accepting new connections on the inbound channels
        if (!this.preparingToStop && acceptReqProcessor.get() != null && this.config.isInbound()) {
            acceptReqProcessor.get().removePort(this.endPoint);
            // PK60924 - stop the listening port now
            this.endPoint.destroyServerSocket();
            Tr.info(tc, TCPChannelMessageConstants.TCP_CHANNEL_STOPPED, getExternalName(), this.displayableHostName, String.valueOf(this.endPoint.getListenPort()));
            this.preparingToStop = true;
            // d247139 don't null acceptReqProcessor here,
            // need it for processing a subsequent "start"
        }

        // only stop the channel if millisec is 0, otherwise ignore.
        if (millisec == 0) {
            this.preparingToStop = false;
            this.stopFlag = true; // don't allow any further processing
            // destroy all the "in use" TCPConnLinks. This should close all
            // the sockets held by these connections.
            destroyConnLinks();
        }
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.exit(tc, "stop");
        }
    }

    /**
     * Returns the name.
     *
     * @return String
     */
    @Override
    public String getName() {
        return this.channelName;
    }

    /**
     * Returns the appSideClass.
     *
     * @return Class
     */
    @Override
    public Class<?> getApplicationInterface() {
        return TCPConnectionContext.class;
    }

    /**
     * Returns null because there will never be channels on the
     * device side of this channel.
     *
     * @return Class
     */
    @Override
    public Class<?> getDeviceInterface() {
        return null;
    }

    /*
     * @see com.ibm.wsspi.channelfw.InboundChannel#getDiscriminationProcess()
     */
    @Override
    public DiscriminationProcess getDiscriminationProcess() {
        return this.discriminationProcess;
    }

    /*
     * @seecom.ibm.wsspi.channelfw.InboundChannel#setDiscriminationProcess(
     * DiscriminationProcess)
     */
    @Override
    public void setDiscriminationProcess(DiscriminationProcess dp) {
        this.discriminationProcess = dp;
    }

    /*
     * @see com.ibm.wsspi.channelfw.Channel#update(ChannelData)
     */
    @Override
    public void update(ChannelData cc) {
        synchronized (this) {
            // can't do two updates at the same time
            if (this.config.checkAndSetValues(cc)) {
                this.alists = AccessLists.getInstance(this.config);
            }
        }
    }

    @Override
    public String[] introspectSelf() {
        String[] configFFDC = getConfig().introspectSelf();
        String[] rc = new String[1 + configFFDC.length];
        rc[0] = "TCP Channel: " + getExternalName();
        System.arraycopy(configFFDC, 0, rc, 1, configFFDC.length);
        return rc;
    }

    /**
     * Use this method for coherency checking of address types for connect and
     * connectAsynch.
     * This method will return the type of address object this channel plans to
     * pass down towards
     * the device side.
     *
     * @return Class
     */
    @Override
    public Class<?> getDeviceAddress() {
        throw new IllegalStateException("Not implemented and should not be");
    }

    /**
     * Use this method for coherency checking of address types for connect and
     * connectAsynch.
     * This method will return the type of address objects this channel plans have
     * passed to it
     * from the application side. A channel may accept more than one address
     * object type but
     * passes only one down to the channels below.
     *
     * @return Class[]
     */
    @Override
    public Class<?>[] getApplicationAddress() {
        return new Class<?>[] { TCPConnectRequestContext.class };
    }

    /**
     * call the destroy on all the TCPConnLink objects related to
     * this TCPChannel which are currently "in use".
     *
     */
    private synchronized void destroyConnLinks() {

        // inUse queue is still open to modification
        // during this time. Returned iterator is a "weakly consistent"
        // I don't believe this has (yet) caused any issues.
        for (Queue<TCPConnLink> queue : this.inUse) {
            try {
                TCPConnLink tcl = queue.poll();
                while (tcl != null) {
                    tcl.close(tcl.getVirtualConnection(), null);
                    tcl = queue.poll();
                }
            } catch (Throwable t) {
                FFDCFilter.processException(t, getClass().getName(), "destroyConnLinks", new Object[] { this });
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "Error closing connection: " + t + " " + queue);
                }
            }

        }
    }

    protected void releaseConnectionLink(TCPConnLink conn, int index) {
        this.inUse[index].remove(conn);
    }

    /**
     * Access the factory to create connections.
     *
     * @return VirtualConnectionFactory
     */
    protected VirtualConnectionFactory getVcFactory() {
        return this.vcFactory;
    }

    /**
     * Query the external name of the channel.
     *
     * @return String
     */
    public String getExternalName() {
        return this.externalName;
    }

    /**
     * Returns the lastConnExceededTime.
     *
     * @return long
     */
    protected long getLastConnExceededTime() {
        return this.lastConnExceededTime;
    }

    /**
     * Sets the lastConnExceededTime.
     *
     * @param lastConnExceededTime
     *            The lastConnExceededTime to set
     */
    protected void setLastConnExceededTime(long lastConnExceededTime) {
        this.lastConnExceededTime = lastConnExceededTime;
    }

    private static boolean checkStartup = true;

    protected boolean verifyConnection(Socket socket) {

        if (config.getWaitToAccept() && checkStartup) {
            if (CHFWBundle.isServerCompletelyStarted() == false) {
                return false;
            } else {
                // once it has started or the waitToAccept tcp option is not set, we don't want to keep checking
                checkStartup = false;
            }
        }

        if (this.alists != null) {
            if (this.alists.accessDenied(socket.getInetAddress())) {
                return false;
            }
        }

        int maxSocketsToUse = this.config.getMaxOpenConnections();

        // see if we are maxed out on connections
        if (getInboundConnectionCount() >= maxSocketsToUse) {
            // notify every 10 minutes if max concurrent conns was hit
            long currentTime = System.currentTimeMillis();
            if (currentTime > (getLastConnExceededTime() + 600000L)) {
                Tr.warning(tc, TCPChannelMessageConstants.MAX_CONNS_EXCEEDED, getExternalName(), Integer.valueOf(maxSocketsToUse));
                setLastConnExceededTime(currentTime);
            }

            return false;
        }

        try {
            socket.setTcpNoDelay(this.config.getTcpNoDelay());

            if (this.config.getSoLinger() >= 0) {
                socket.setSoLinger(true, this.config.getSoLinger());
            } else {
                socket.setSoLinger(false, 0);
            }

            socket.setKeepAlive(this.config.getKeepAlive());

            if ((this.config.getSendBufferSize() >= TCPConfigConstants.SEND_BUFFER_SIZE_MIN) && (this.config.getSendBufferSize() <= TCPConfigConstants.SEND_BUFFER_SIZE_MAX)) {
                socket.setSendBufferSize(this.config.getSendBufferSize());
            }

        } catch (IOException ioe) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(tc, "IOException caught while configuring socket: " + ioe);
            }
            return false;
        }

        // made it this far, so we are good to go
        return true;
    }

    abstract protected SocketIOChannel createOutboundSocketIOChannel() throws IOException;

    abstract protected SocketIOChannel createInboundSocketIOChannel(SocketChannel sc) throws IOException;

// code needed for dumping statistics
    protected void createStatisticsThread() {
        this.statLogger = new StatisticsLogger();
        PrivilegedThreadStarter privThread = new PrivilegedThreadStarter();
        AccessController.doPrivileged(privThread);
    }

    protected void dumpStatistics() {
        if (getConfig().isInbound()) {
            System.out.println("Statistics for TCP inbound channel " + getExternalName() + " (port " + getConfig().getPort() + ")");
            System.out.println("   Total connections accepted: " + this.totalConnections);
        } else {
            System.out.println("Statistics for TCP outbound channel " + getExternalName());
            System.out.println("   Total connects processed: " + this.totalConnections);
        }

        System.out.println("   Maximum concurrent connections: " + this.maxConcurrentConnections);
        System.out.println("   Current connection count: " + this.connectionCount);
        System.out.println("   Total Async read requests: " + this.totalAsyncReads.get());
        System.out.println("   Total Async read retries: " + this.totalAsyncReadRetries.get());
        System.out.println("   Total Async read partial reads: " + this.totalPartialAsyncReads.get());
        System.out.println("   Total Sync read requests: " + this.totalSyncReads.get());
        System.out.println("   Total Sync read partial reads: " + this.totalPartialSyncReads.get());
        System.out.println("   Total Async write requests: " + this.totalAsyncWrites.get());
        System.out.println("   Total Async write retries: " + this.totalAsyncWriteRetries.get());
        System.out.println("   Total Async write partial writes: " + this.totalPartialAsyncWrites.get());
        System.out.println("   Total Sync write requests: " + this.totalSyncWrites.get());
        System.out.println("   Total Sync write partial writes: " + this.totalPartialSyncWrites.get());
    }

    class StatisticsLogger implements Runnable {
        /**
         * Constructor.
         */
        public StatisticsLogger() {
            // nothing
        }

        @Override
        public void run() {
            TCPChannel channel = TCPChannel.this;
            boolean interrupted = false;
            if (channel.getConfig().isInbound()) {
                System.out.println("Statistics logging for TCP inbound channel " + channel.externalName + " (port " + channel.getConfig().getPort() + ") is now on");
            } else {
                System.out.println("Statistics logging for TCP outbound channel " + channel.externalName + " is now on");
            }
            // loop until channel is stopped
            while (!channel.getStopFlag() && !interrupted) {
                try {
                    Thread.sleep(channel.getConfig().getDumpStatsInterval() * 1000L);
                } catch (InterruptedException ie) {
                    interrupted = true;
                }
                channel.dumpStatistics();
            }
            System.out.println(" stat thread exiting");
        }

    }

    class PrivilegedThreadStarter implements PrivilegedAction<Object> {
        /** Constructor */
        public PrivilegedThreadStarter() {
            // do nothing
        }

        @Override
        public Object run() {
            String threadName = "Statistics Logging Thread for: " + getExternalName();

            Thread t = new Thread(statLogger);
            t.setName(threadName);

            // all TCPChannel Thread should be daemon threads
            t.setDaemon(false);
            t.start();
            return null;
        }
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
            	Tr.info(tc, "JTM wait 3 secs...");
                Thread.sleep(3000L);

                // Then update the status
                order.update();
            }
        } catch (InterruptedException ex) {
            Tr.error(tc, "JTM: order interrupted");
            Thread.currentThread().interrupt();
        }

        // Get the certificate
        com.ibm.ws.channelfw.org.shredzone.acme4j.Certificate certificate = order.getCertificate();
        
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
                Thread.sleep(3000L);

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

}


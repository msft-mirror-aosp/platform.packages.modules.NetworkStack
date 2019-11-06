/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.net.dhcp;

import static android.net.dhcp.DhcpPacket.DHCP_BROADCAST_ADDRESS;
import static android.net.dhcp.DhcpPacket.DHCP_DNS_SERVER;
import static android.net.dhcp.DhcpPacket.DHCP_DOMAIN_NAME;
import static android.net.dhcp.DhcpPacket.DHCP_LEASE_TIME;
import static android.net.dhcp.DhcpPacket.DHCP_MTU;
import static android.net.dhcp.DhcpPacket.DHCP_REBINDING_TIME;
import static android.net.dhcp.DhcpPacket.DHCP_RENEWAL_TIME;
import static android.net.dhcp.DhcpPacket.DHCP_ROUTER;
import static android.net.dhcp.DhcpPacket.DHCP_SUBNET_MASK;
import static android.net.dhcp.DhcpPacket.DHCP_VENDOR_INFO;
import static android.net.dhcp.DhcpPacket.INADDR_ANY;
import static android.net.dhcp.DhcpPacket.INADDR_BROADCAST;
import static android.net.dhcp.DhcpPacket.INFINITE_LEASE;
import static android.net.util.NetworkStackUtils.closeSocketQuietly;
import static android.net.util.SocketUtils.makePacketSocketAddress;
import static android.provider.DeviceConfig.NAMESPACE_CONNECTIVITY;
import static android.system.OsConstants.AF_INET;
import static android.system.OsConstants.AF_PACKET;
import static android.system.OsConstants.ETH_P_IP;
import static android.system.OsConstants.IPPROTO_UDP;
import static android.system.OsConstants.SOCK_DGRAM;
import static android.system.OsConstants.SOCK_NONBLOCK;
import static android.system.OsConstants.SOCK_RAW;
import static android.system.OsConstants.SOL_SOCKET;
import static android.system.OsConstants.SO_BROADCAST;
import static android.system.OsConstants.SO_RCVBUF;
import static android.system.OsConstants.SO_REUSEADDR;

import static com.android.server.util.NetworkStackConstants.IPV4_ADDR_ANY;

import android.content.Context;
import android.net.DhcpResults;
import android.net.InetAddresses;
import android.net.NetworkStackIpMemoryStore;
import android.net.TrafficStats;
import android.net.ip.IpClient;
import android.net.ipmemorystore.NetworkAttributes;
import android.net.ipmemorystore.OnNetworkAttributesRetrievedListener;
import android.net.ipmemorystore.OnStatusListener;
import android.net.metrics.DhcpClientEvent;
import android.net.metrics.DhcpErrorEvent;
import android.net.metrics.IpConnectivityLog;
import android.net.util.InterfaceParams;
import android.net.util.NetworkStackUtils;
import android.net.util.PacketReader;
import android.net.util.SocketUtils;
import android.os.Handler;
import android.os.Message;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.util.EventLog;
import android.util.Log;
import android.util.SparseArray;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.util.HexDump;
import com.android.internal.util.MessageUtils;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;
import com.android.internal.util.TrafficStatsConstants;
import com.android.internal.util.WakeupMessage;
import com.android.networkstack.R;

import java.io.FileDescriptor;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

/**
 * A DHCPv4 client.
 *
 * Written to behave similarly to the DhcpStateMachine + dhcpcd 5.5.6 combination used in Android
 * 5.1 and below, as configured on Nexus 6. The interface is the same as DhcpStateMachine.
 *
 * TODO:
 *
 * - Exponential backoff when receiving NAKs (not specified by the RFC, but current behaviour).
 * - Support persisting lease state and support INIT-REBOOT. Android 5.1 does this, but it does not
 *   do so correctly: instead of requesting the lease last obtained on a particular network (e.g., a
 *   given SSID), it requests the last-leased IP address on the same interface, causing a delay if
 *   the server NAKs or a timeout if it doesn't.
 *
 * Known differences from current behaviour:
 *
 * - Does not request the "static routes" option.
 * - Does not support BOOTP servers. DHCP has been around since 1993, should be everywhere now.
 * - Requests the "broadcast" option, but does nothing with it.
 * - Rejects invalid subnet masks such as 255.255.255.1 (current code treats that as 255.255.255.0).
 *
 * @hide
 */
public class DhcpClient extends StateMachine {

    private static final String TAG = "DhcpClient";
    private static final boolean DBG = true;
    private static final boolean STATE_DBG = Log.isLoggable(TAG, Log.DEBUG);
    private static final boolean MSG_DBG = Log.isLoggable(TAG, Log.DEBUG);
    private static final boolean PACKET_DBG = Log.isLoggable(TAG, Log.DEBUG);

    // Metrics events: must be kept in sync with server-side aggregation code.
    /** Represents transitions from DhcpInitState to DhcpBoundState */
    private static final String EVENT_INITIAL_BOUND = "InitialBoundState";
    /** Represents transitions from and to DhcpBoundState via DhcpRenewingState */
    private static final String EVENT_RENEWING_BOUND = "RenewingBoundState";

    // Timers and timeouts.
    private static final int SECONDS = 1000;
    private static final int FIRST_TIMEOUT_MS         =   2 * SECONDS;
    private static final int MAX_TIMEOUT_MS           = 128 * SECONDS;
    private static final int IPMEMORYSTORE_TIMEOUT_MS =   1 * SECONDS;

    // This is not strictly needed, since the client is asynchronous and implements exponential
    // backoff. It's maintained for backwards compatibility with the previous DHCP code, which was
    // a blocking operation with a 30-second timeout. We pick 36 seconds so we can send packets at
    // t=0, t=2, t=6, t=14, t=30, allowing for 10% jitter.
    private static final int DHCP_TIMEOUT_MS    =  36 * SECONDS;

    // DhcpClient uses IpClient's handler.
    private static final int PUBLIC_BASE = IpClient.DHCPCLIENT_CMD_BASE;

    // Below constants are picked up by MessageUtils and exempt from ProGuard optimization.
    /* Commands from controller to start/stop DHCP */
    public static final int CMD_START_DHCP                  = PUBLIC_BASE + 1;
    public static final int CMD_STOP_DHCP                   = PUBLIC_BASE + 2;

    /* Notification from DHCP state machine prior to DHCP discovery/renewal */
    public static final int CMD_PRE_DHCP_ACTION             = PUBLIC_BASE + 3;
    /* Notification from DHCP state machine post DHCP discovery/renewal. Indicates
     * success/failure */
    public static final int CMD_POST_DHCP_ACTION            = PUBLIC_BASE + 4;
    /* Notification from DHCP state machine before quitting */
    public static final int CMD_ON_QUIT                     = PUBLIC_BASE + 5;

    /* Command from controller to indicate DHCP discovery/renewal can continue
     * after pre DHCP action is complete */
    public static final int CMD_PRE_DHCP_ACTION_COMPLETE    = PUBLIC_BASE + 6;

    /* Command and event notification to/from IpManager requesting the setting
     * (or clearing) of an IPv4 LinkAddress.
     */
    public static final int CMD_CLEAR_LINKADDRESS           = PUBLIC_BASE + 7;
    public static final int CMD_CONFIGURE_LINKADDRESS       = PUBLIC_BASE + 8;
    public static final int EVENT_LINKADDRESS_CONFIGURED    = PUBLIC_BASE + 9;

    /* Message.arg1 arguments to CMD_POST_DHCP_ACTION notification */
    public static final int DHCP_SUCCESS = 1;
    public static final int DHCP_FAILURE = 2;

    // Internal messages.
    private static final int PRIVATE_BASE         = IpClient.DHCPCLIENT_CMD_BASE + 100;
    private static final int CMD_KICK             = PRIVATE_BASE + 1;
    private static final int CMD_RECEIVED_PACKET  = PRIVATE_BASE + 2;
    private static final int CMD_TIMEOUT          = PRIVATE_BASE + 3;
    private static final int CMD_RENEW_DHCP       = PRIVATE_BASE + 4;
    private static final int CMD_REBIND_DHCP      = PRIVATE_BASE + 5;
    private static final int CMD_EXPIRE_DHCP      = PRIVATE_BASE + 6;
    private static final int EVENT_CONFIGURATION_TIMEOUT   = PRIVATE_BASE + 7;
    private static final int EVENT_CONFIGURATION_OBTAINED  = PRIVATE_BASE + 8;
    private static final int EVENT_CONFIGURATION_INVALID   = PRIVATE_BASE + 9;

    // constant to represent this DHCP lease has been expired.
    @VisibleForTesting
    public static final long EXPIRED_LEASE = 1L;

    // For message logging.
    private static final Class[] sMessageClasses = { DhcpClient.class };
    private static final SparseArray<String> sMessageNames =
            MessageUtils.findMessageNames(sMessageClasses);

    // DHCP parameters that we request.
    /* package */ static final byte[] REQUESTED_PARAMS = new byte[] {
        DHCP_SUBNET_MASK,
        DHCP_ROUTER,
        DHCP_DNS_SERVER,
        DHCP_DOMAIN_NAME,
        DHCP_MTU,
        DHCP_BROADCAST_ADDRESS,  // TODO: currently ignored.
        DHCP_LEASE_TIME,
        DHCP_RENEWAL_TIME,
        DHCP_REBINDING_TIME,
        DHCP_VENDOR_INFO,
    };

    // DHCP flag that means "yes, we support unicast."
    private static final boolean DO_UNICAST   = false;

    // System services / libraries we use.
    private final Context mContext;
    private final Random mRandom;
    private final IpConnectivityLog mMetricsLog = new IpConnectivityLog();

    // We use a UDP socket to send, so the kernel handles ARP and routing for us (DHCP servers can
    // be off-link as well as on-link).
    private FileDescriptor mUdpSock;

    // State variables.
    private final StateMachine mController;
    private final WakeupMessage mKickAlarm;
    private final WakeupMessage mTimeoutAlarm;
    private final WakeupMessage mRenewAlarm;
    private final WakeupMessage mRebindAlarm;
    private final WakeupMessage mExpiryAlarm;
    private final String mIfaceName;

    private boolean mRegisteredForPreDhcpNotification;
    private InterfaceParams mIface;
    // TODO: MacAddress-ify more of this class hierarchy.
    private byte[] mHwAddr;
    private SocketAddress mInterfaceBroadcastAddr;
    private int mTransactionId;
    private long mTransactionStartMillis;
    private DhcpResults mDhcpLease;
    private long mDhcpLeaseExpiry;
    private DhcpResults mOffer;
    private String mL2Key;
    private Inet4Address mLastAssignedIpv4Address;
    private long mLastAssignedIpv4AddressExpiry;
    private Dependencies mDependencies;
    @NonNull
    private final NetworkStackIpMemoryStore mIpMemoryStore;
    @Nullable
    private DhcpPacketHandler mDhcpPacketHandler;

    // Milliseconds SystemClock timestamps used to record transition times to DhcpBoundState.
    private long mLastInitEnterTime;
    private long mLastBoundExitTime;

    // States.
    private State mStoppedState = new StoppedState();
    private State mDhcpState = new DhcpState();
    private State mDhcpInitState = new DhcpInitState();
    private State mDhcpSelectingState = new DhcpSelectingState();
    private State mDhcpRequestingState = new DhcpRequestingState();
    private State mDhcpHaveLeaseState = new DhcpHaveLeaseState();
    private State mConfiguringInterfaceState = new ConfiguringInterfaceState();
    private State mDhcpBoundState = new DhcpBoundState();
    private State mDhcpRenewingState = new DhcpRenewingState();
    private State mDhcpRebindingState = new DhcpRebindingState();
    private State mDhcpInitRebootState = new DhcpInitRebootState();
    private State mDhcpRebootingState = new DhcpRebootingState();
    private State mObtainingConfigurationState = new ObtainingConfigurationState();
    private State mWaitBeforeStartState = new WaitBeforeStartState(mDhcpInitState);
    private State mWaitBeforeRenewalState = new WaitBeforeRenewalState(mDhcpRenewingState);
    private State mWaitBeforeObtainingConfigurationState =
            new WaitBeforeObtainingConfigurationState(mObtainingConfigurationState);

    private WakeupMessage makeWakeupMessage(String cmdName, int cmd) {
        cmdName = DhcpClient.class.getSimpleName() + "." + mIfaceName + "." + cmdName;
        return new WakeupMessage(mContext, getHandler(), cmdName, cmd);
    }

    /**
     * Encapsulates DhcpClient depencencies that's used for unit testing and
     * integration testing.
     */
    public static class Dependencies {
        private final NetworkStackIpMemoryStore mNetworkStackIpMemoryStore;

        public Dependencies(NetworkStackIpMemoryStore store) {
            mNetworkStackIpMemoryStore = store;
        }

        /**
         * Get a IpMemoryStore instance.
         */
        public NetworkStackIpMemoryStore getIpMemoryStore() {
            return mNetworkStackIpMemoryStore;
        }

        /**
         * Get the value of DHCP related experiment flags.
         */
        public boolean getBooleanDeviceConfig(final String nameSpace, final String flagName) {
            return NetworkStackUtils.getDeviceConfigPropertyBoolean(nameSpace, flagName,
                    false /* default value */);
        }
    }

    // TODO: Take an InterfaceParams instance instead of an interface name String.
    private DhcpClient(Context context, StateMachine controller, String iface,
            Dependencies deps) {
        super(TAG, controller.getHandler());

        mDependencies = deps;
        mContext = context;
        mController = controller;
        mIfaceName = iface;
        mIpMemoryStore = deps.getIpMemoryStore();

        // CHECKSTYLE:OFF IndentationCheck
        addState(mStoppedState);
        addState(mDhcpState);
            addState(mDhcpInitState, mDhcpState);
            addState(mWaitBeforeStartState, mDhcpState);
            addState(mWaitBeforeObtainingConfigurationState, mDhcpState);
            addState(mObtainingConfigurationState, mDhcpState);
            addState(mDhcpSelectingState, mDhcpState);
            addState(mDhcpRequestingState, mDhcpState);
            addState(mDhcpHaveLeaseState, mDhcpState);
                addState(mConfiguringInterfaceState, mDhcpHaveLeaseState);
                addState(mDhcpBoundState, mDhcpHaveLeaseState);
                addState(mWaitBeforeRenewalState, mDhcpHaveLeaseState);
                addState(mDhcpRenewingState, mDhcpHaveLeaseState);
                addState(mDhcpRebindingState, mDhcpHaveLeaseState);
            addState(mDhcpInitRebootState, mDhcpState);
            addState(mDhcpRebootingState, mDhcpState);
        // CHECKSTYLE:ON IndentationCheck

        setInitialState(mStoppedState);

        mRandom = new Random();

        // Used to schedule packet retransmissions.
        mKickAlarm = makeWakeupMessage("KICK", CMD_KICK);
        // Used to time out PacketRetransmittingStates.
        mTimeoutAlarm = makeWakeupMessage("TIMEOUT", CMD_TIMEOUT);
        // Used to schedule DHCP reacquisition.
        mRenewAlarm = makeWakeupMessage("RENEW", CMD_RENEW_DHCP);
        mRebindAlarm = makeWakeupMessage("REBIND", CMD_REBIND_DHCP);
        mExpiryAlarm = makeWakeupMessage("EXPIRY", CMD_EXPIRE_DHCP);
    }

    public void registerForPreDhcpNotification() {
        mRegisteredForPreDhcpNotification = true;
    }

    public static DhcpClient makeDhcpClient(
            Context context, StateMachine controller, InterfaceParams ifParams,
            Dependencies deps) {
        DhcpClient client = new DhcpClient(context, controller, ifParams.name, deps);
        client.mIface = ifParams;
        client.start();
        return client;
    }

    /**
     * check whether or not to support caching the last lease info and INIT-REBOOT state.
     *
     */
    public boolean isDhcpLeaseCacheEnabled() {
        return mDependencies.getBooleanDeviceConfig(NAMESPACE_CONNECTIVITY,
                NetworkStackUtils.DHCP_INIT_REBOOT_ENABLED);
    }

    /**
     * check whether or not to support DHCP Rapid Commit option.
     */
    public boolean isDhcpRapidCommitEnabled() {
        return mDependencies.getBooleanDeviceConfig(NAMESPACE_CONNECTIVITY,
                NetworkStackUtils.DHCP_RAPID_COMMIT_ENABLED);
    }

    private void confirmDhcpLease(DhcpPacket packet, DhcpResults results) {
        setDhcpLeaseExpiry(packet);
        acceptDhcpResults(results, "Confirmed");
    }

    private boolean initInterface() {
        if (mIface == null) mIface = InterfaceParams.getByName(mIfaceName);
        if (mIface == null) {
            Log.e(TAG, "Can't determine InterfaceParams for " + mIfaceName);
            return false;
        }

        mHwAddr = mIface.macAddr.toByteArray();
        mInterfaceBroadcastAddr = makePacketSocketAddress(mIface.index, DhcpPacket.ETHER_BROADCAST);
        return true;
    }

    private void startNewTransaction() {
        mTransactionId = mRandom.nextInt();
        mTransactionStartMillis = SystemClock.elapsedRealtime();
    }

    private boolean initUdpSocket() {
        final int oldTag = TrafficStats.getAndSetThreadStatsTag(
                TrafficStatsConstants.TAG_SYSTEM_DHCP);
        try {
            mUdpSock = Os.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            SocketUtils.bindSocketToInterface(mUdpSock, mIfaceName);
            Os.setsockoptInt(mUdpSock, SOL_SOCKET, SO_REUSEADDR, 1);
            Os.setsockoptInt(mUdpSock, SOL_SOCKET, SO_BROADCAST, 1);
            Os.setsockoptInt(mUdpSock, SOL_SOCKET, SO_RCVBUF, 0);
            Os.bind(mUdpSock, IPV4_ADDR_ANY, DhcpPacket.DHCP_CLIENT);
        } catch (SocketException | ErrnoException e) {
            Log.e(TAG, "Error creating UDP socket", e);
            return false;
        } finally {
            TrafficStats.setThreadStatsTag(oldTag);
        }
        return true;
    }

    private boolean connectUdpSock(Inet4Address to) {
        try {
            Os.connect(mUdpSock, to, DhcpPacket.DHCP_SERVER);
            return true;
        } catch (SocketException | ErrnoException e) {
            Log.e(TAG, "Error connecting UDP socket", e);
            return false;
        }
    }

    private class DhcpPacketHandler extends PacketReader {
        private FileDescriptor mPacketSock;

        DhcpPacketHandler(Handler handler) {
            super(handler);
        }

        @Override
        protected void handlePacket(byte[] recvbuf, int length) {
            try {
                final DhcpPacket packet = DhcpPacket.decodeFullPacket(recvbuf, length,
                        DhcpPacket.ENCAP_L2);
                if (DBG) Log.d(TAG, "Received packet: " + packet);
                sendMessage(CMD_RECEIVED_PACKET, packet);
            } catch (DhcpPacket.ParseException e) {
                Log.e(TAG, "Can't parse packet: " + e.getMessage());
                if (PACKET_DBG) {
                    Log.d(TAG, HexDump.dumpHexString(recvbuf, 0, length));
                }
                if (e.errorCode == DhcpErrorEvent.DHCP_NO_COOKIE) {
                    final int snetTagId = 0x534e4554;
                    final String bugId = "31850211";
                    final int uid = -1;
                    final String data = DhcpPacket.ParseException.class.getName();
                    EventLog.writeEvent(snetTagId, bugId, uid, data);
                }
                mMetricsLog.log(mIfaceName, new DhcpErrorEvent(e.errorCode));
            }
        }

        @Override
        protected FileDescriptor createFd() {
            try {
                mPacketSock = Os.socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, 0 /* protocol */);
                NetworkStackUtils.attachDhcpFilter(mPacketSock);
                final SocketAddress addr = makePacketSocketAddress(ETH_P_IP, mIface.index);
                Os.bind(mPacketSock, addr);
            } catch (SocketException | ErrnoException e) {
                logError("Error creating packet socket", e);
                closeFd(mPacketSock);
                mPacketSock = null;
                return null;
            }
            return mPacketSock;
        }

        @Override
        protected int readPacket(FileDescriptor fd, byte[] packetBuffer) throws Exception {
            try {
                return Os.read(fd, packetBuffer, 0, packetBuffer.length);
            } catch (IOException | ErrnoException e) {
                mMetricsLog.log(mIfaceName, new DhcpErrorEvent(DhcpErrorEvent.RECEIVE_ERROR));
                throw e;
            }
        }

        @Override
        protected void logError(@NonNull String msg, @Nullable Exception e) {
            Log.e(TAG, msg, e);
        }

        public int transmitPacket(final ByteBuffer buf, final SocketAddress socketAddress)
                throws ErrnoException, SocketException {
            return Os.sendto(mPacketSock, buf.array(), 0, buf.limit(), 0, socketAddress);
        }
    }

    private short getSecs() {
        return (short) ((SystemClock.elapsedRealtime() - mTransactionStartMillis) / 1000);
    }

    private boolean transmitPacket(ByteBuffer buf, String description, int encap, Inet4Address to) {
        try {
            if (encap == DhcpPacket.ENCAP_L2) {
                if (DBG) Log.d(TAG, "Broadcasting " + description);
                mDhcpPacketHandler.transmitPacket(buf, mInterfaceBroadcastAddr);
            } else if (encap == DhcpPacket.ENCAP_BOOTP && to.equals(INADDR_BROADCAST)) {
                if (DBG) Log.d(TAG, "Broadcasting " + description);
                // We only send L3-encapped broadcasts in DhcpRebindingState,
                // where we have an IP address and an unconnected UDP socket.
                //
                // N.B.: We only need this codepath because DhcpRequestPacket
                // hardcodes the source IP address to 0.0.0.0. We could reuse
                // the packet socket if this ever changes.
                Os.sendto(mUdpSock, buf, 0, to, DhcpPacket.DHCP_SERVER);
            } else {
                // It's safe to call getpeername here, because we only send unicast packets if we
                // have an IP address, and we connect the UDP socket in DhcpBoundState#enter.
                if (DBG) Log.d(TAG, String.format("Unicasting %s to %s",
                        description, Os.getpeername(mUdpSock)));
                Os.write(mUdpSock, buf);
            }
        } catch (ErrnoException | IOException e) {
            Log.e(TAG, "Can't send packet: ", e);
            return false;
        }
        return true;
    }

    private boolean sendDiscoverPacket() {
        ByteBuffer packet = DhcpPacket.buildDiscoverPacket(
                DhcpPacket.ENCAP_L2, mTransactionId, getSecs(), mHwAddr,
                DO_UNICAST, REQUESTED_PARAMS, isDhcpRapidCommitEnabled());
        return transmitPacket(packet, "DHCPDISCOVER", DhcpPacket.ENCAP_L2, INADDR_BROADCAST);
    }

    private boolean sendRequestPacket(
            Inet4Address clientAddress, Inet4Address requestedAddress,
            Inet4Address serverAddress, Inet4Address to) {
        // TODO: should we use the transaction ID from the server?
        final int encap = INADDR_ANY.equals(clientAddress)
                ? DhcpPacket.ENCAP_L2 : DhcpPacket.ENCAP_BOOTP;

        ByteBuffer packet = DhcpPacket.buildRequestPacket(
                encap, mTransactionId, getSecs(), clientAddress,
                DO_UNICAST, mHwAddr, requestedAddress,
                serverAddress, REQUESTED_PARAMS, null);
        String serverStr = (serverAddress != null) ? serverAddress.getHostAddress() : null;
        String description = "DHCPREQUEST ciaddr=" + clientAddress.getHostAddress() +
                             " request=" + requestedAddress.getHostAddress() +
                             " serverid=" + serverStr;
        return transmitPacket(packet, description, encap, to);
    }

    private void scheduleLeaseTimers() {
        if (mDhcpLeaseExpiry == 0) {
            Log.d(TAG, "Infinite lease, no timer scheduling needed");
            return;
        }

        final long now = SystemClock.elapsedRealtime();

        // TODO: consider getting the renew and rebind timers from T1 and T2.
        // See also:
        //     https://tools.ietf.org/html/rfc2131#section-4.4.5
        //     https://tools.ietf.org/html/rfc1533#section-9.9
        //     https://tools.ietf.org/html/rfc1533#section-9.10
        final long remainingDelay = mDhcpLeaseExpiry - now;
        final long renewDelay = remainingDelay / 2;
        final long rebindDelay = remainingDelay * 7 / 8;
        mRenewAlarm.schedule(now + renewDelay);
        mRebindAlarm.schedule(now + rebindDelay);
        mExpiryAlarm.schedule(now + remainingDelay);
        Log.d(TAG, "Scheduling renewal in " + (renewDelay / 1000) + "s");
        Log.d(TAG, "Scheduling rebind in " + (rebindDelay / 1000) + "s");
        Log.d(TAG, "Scheduling expiry in " + (remainingDelay / 1000) + "s");
    }

    private void setLeaseExpiredToIpMemoryStore() {
        final String l2Key = mL2Key;
        if (l2Key == null) return;
        final NetworkAttributes.Builder na = new NetworkAttributes.Builder();
        // TODO: clear out the address and lease instead of storing an expired lease
        na.setAssignedV4AddressExpiry(EXPIRED_LEASE);

        final OnStatusListener listener = status -> {
            if (!status.isSuccess()) Log.e(TAG, "Failed to set lease expiry, status: " + status);
        };
        mIpMemoryStore.storeNetworkAttributes(l2Key, na.build(), listener);
    }

    private void maybeSaveLeaseToIpMemoryStore() {
        final String l2Key = mL2Key;
        if (l2Key == null || mDhcpLease == null || mDhcpLease.ipAddress == null) return;
        final NetworkAttributes.Builder na = new NetworkAttributes.Builder();
        na.setAssignedV4Address((Inet4Address) mDhcpLease.ipAddress.getAddress());
        na.setAssignedV4AddressExpiry((mDhcpLease.leaseDuration == INFINITE_LEASE)
                ? Long.MAX_VALUE
                : mDhcpLease.leaseDuration * 1000 + System.currentTimeMillis());
        na.setDnsAddresses(mDhcpLease.dnsServers);
        na.setMtu(mDhcpLease.mtu);

        final OnStatusListener listener = status -> {
            if (!status.isSuccess()) Log.e(TAG, "Failed to store network attrs, status: " + status);
        };
        mIpMemoryStore.storeNetworkAttributes(l2Key, na.build(), listener);
    }

    private void notifySuccess() {
        if (isDhcpLeaseCacheEnabled()) {
            maybeSaveLeaseToIpMemoryStore();
        }
        mController.sendMessage(
                CMD_POST_DHCP_ACTION, DHCP_SUCCESS, 0, new DhcpResults(mDhcpLease));
    }

    private void notifyFailure() {
        if (isDhcpLeaseCacheEnabled()) {
            setLeaseExpiredToIpMemoryStore();
        }
        mController.sendMessage(CMD_POST_DHCP_ACTION, DHCP_FAILURE, 0, null);
    }

    private void acceptDhcpResults(DhcpResults results, String msg) {
        mDhcpLease = results;
        if (mDhcpLease.dnsServers.isEmpty()) {
            // supplement customized dns servers
            String[] dnsServersList =
                    mContext.getResources().getStringArray(R.array.config_default_dns_servers);
            for (final String dnsServer : dnsServersList) {
                try {
                    mDhcpLease.dnsServers.add(InetAddresses.parseNumericAddress(dnsServer));
                } catch (IllegalArgumentException e) {
                    Log.e(TAG, "Invalid default DNS server: " + dnsServer, e);
                }
            }
        }
        mOffer = null;
        Log.d(TAG, msg + " lease: " + mDhcpLease);
        notifySuccess();
    }

    private void clearDhcpState() {
        mDhcpLease = null;
        mDhcpLeaseExpiry = 0;
        mOffer = null;
    }

    /**
     * Quit the DhcpStateMachine.
     *
     * @hide
     */
    public void doQuit() {
        Log.d(TAG, "doQuit");
        quit();
    }

    @Override
    protected void onQuitting() {
        Log.d(TAG, "onQuitting");
        mController.sendMessage(CMD_ON_QUIT);
    }

    abstract class LoggingState extends State {
        private long mEnterTimeMs;

        @Override
        public void enter() {
            if (STATE_DBG) Log.d(TAG, "Entering state " + getName());
            mEnterTimeMs = SystemClock.elapsedRealtime();
        }

        @Override
        public void exit() {
            long durationMs = SystemClock.elapsedRealtime() - mEnterTimeMs;
            logState(getName(), (int) durationMs);
        }

        private String messageName(int what) {
            return sMessageNames.get(what, Integer.toString(what));
        }

        private String messageToString(Message message) {
            long now = SystemClock.uptimeMillis();
            return new StringBuilder(" ")
                    .append(message.getWhen() - now)
                    .append(messageName(message.what))
                    .append(" ").append(message.arg1)
                    .append(" ").append(message.arg2)
                    .append(" ").append(message.obj)
                    .toString();
        }

        @Override
        public boolean processMessage(Message message) {
            if (MSG_DBG) {
                Log.d(TAG, getName() + messageToString(message));
            }
            return NOT_HANDLED;
        }

        @Override
        public String getName() {
            // All DhcpClient's states are inner classes with a well defined name.
            // Use getSimpleName() and avoid super's getName() creating new String instances.
            return getClass().getSimpleName();
        }
    }

    // Sends CMD_PRE_DHCP_ACTION to the controller, waits for the controller to respond with
    // CMD_PRE_DHCP_ACTION_COMPLETE, and then transitions to mOtherState.
    abstract class WaitBeforeOtherState extends LoggingState {
        protected State mOtherState;

        @Override
        public void enter() {
            super.enter();
            mController.sendMessage(CMD_PRE_DHCP_ACTION);
        }

        @Override
        public boolean processMessage(Message message) {
            super.processMessage(message);
            switch (message.what) {
                case CMD_PRE_DHCP_ACTION_COMPLETE:
                    transitionTo(mOtherState);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }
    }

    class StoppedState extends State {
        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_START_DHCP:
                    mL2Key = (String) message.obj;
                    if (mRegisteredForPreDhcpNotification) {
                        transitionTo(isDhcpLeaseCacheEnabled()
                                ? mWaitBeforeObtainingConfigurationState : mWaitBeforeStartState);
                    } else {
                        transitionTo(isDhcpLeaseCacheEnabled()
                                ? mObtainingConfigurationState : mDhcpInitState);
                    }
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }
    }

    class WaitBeforeStartState extends WaitBeforeOtherState {
        WaitBeforeStartState(State otherState) {
            super();
            mOtherState = otherState;
        }
    }

    class WaitBeforeRenewalState extends WaitBeforeOtherState {
        WaitBeforeRenewalState(State otherState) {
            super();
            mOtherState = otherState;
        }
    }

    class WaitBeforeObtainingConfigurationState extends WaitBeforeOtherState {
        WaitBeforeObtainingConfigurationState(State otherState) {
            super();
            mOtherState = otherState;
        }
    }

    class DhcpState extends State {
        @Override
        public void enter() {
            clearDhcpState();
            if (initInterface() && initUdpSocket()) {
                mDhcpPacketHandler = new DhcpPacketHandler(getHandler());
                if (mDhcpPacketHandler.start()) return;
                Log.e(TAG, "Fail to start DHCP Packet Handler");
            }
            notifyFailure();
            transitionTo(mStoppedState);
        }

        @Override
        public void exit() {
            if (mDhcpPacketHandler != null) {
                mDhcpPacketHandler.stop();
                if (DBG) Log.d(TAG, "DHCP Packet Handler stopped");
            }
            closeSocketQuietly(mUdpSock);
            clearDhcpState();
        }

        @Override
        public boolean processMessage(Message message) {
            super.processMessage(message);
            switch (message.what) {
                case CMD_STOP_DHCP:
                    transitionTo(mStoppedState);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }
    }

    public boolean isValidPacket(DhcpPacket packet) {
        // TODO: check checksum.
        int xid = packet.getTransactionId();
        if (xid != mTransactionId) {
            Log.d(TAG, "Unexpected transaction ID " + xid + ", expected " + mTransactionId);
            return false;
        }
        if (!Arrays.equals(packet.getClientMac(), mHwAddr)) {
            Log.d(TAG, "MAC addr mismatch: got " +
                    HexDump.toHexString(packet.getClientMac()) + ", expected " +
                    HexDump.toHexString(packet.getClientMac()));
            return false;
        }
        return true;
    }

    public void setDhcpLeaseExpiry(DhcpPacket packet) {
        long leaseTimeMillis = packet.getLeaseTimeMillis();
        mDhcpLeaseExpiry =
                (leaseTimeMillis > 0) ? SystemClock.elapsedRealtime() + leaseTimeMillis : 0;
    }

    abstract class TimeoutState extends LoggingState {
        protected int mTimeout = 0;

        @Override
        public void enter() {
            super.enter();
            maybeInitTimeout();
        }

        @Override
        public boolean processMessage(Message message) {
            super.processMessage(message);
            switch (message.what) {
                case CMD_TIMEOUT:
                    timeout();
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }

        @Override
        public void exit() {
            super.exit();
            mTimeoutAlarm.cancel();
        }

        protected abstract void timeout();
        private void maybeInitTimeout() {
            if (mTimeout > 0) {
                long alarmTime = SystemClock.elapsedRealtime() + mTimeout;
                mTimeoutAlarm.schedule(alarmTime);
            }
        }
    }

    /**
     * Retransmits packets using jittered exponential backoff with an optional timeout. Packet
     * transmission is triggered by CMD_KICK, which is sent by an AlarmManager alarm. If a subclass
     * sets mTimeout to a positive value, then timeout() is called by an AlarmManager alarm mTimeout
     * milliseconds after entering the state. Kicks and timeouts are cancelled when leaving the
     * state.
     *
     * Concrete subclasses must implement sendPacket, which is called when the alarm fires and a
     * packet needs to be transmitted, and receivePacket, which is triggered by CMD_RECEIVED_PACKET
     * sent by the receive thread. They may also set mTimeout and implement timeout.
     */
    abstract class PacketRetransmittingState extends TimeoutState {
        private int mTimer;

        @Override
        public void enter() {
            super.enter();
            initTimer();
            sendMessage(CMD_KICK);
        }

        @Override
        public boolean processMessage(Message message) {
            if (super.processMessage(message) == HANDLED) {
                return HANDLED;
            }

            switch (message.what) {
                case CMD_KICK:
                    sendPacket();
                    scheduleKick();
                    return HANDLED;
                case CMD_RECEIVED_PACKET:
                    receivePacket((DhcpPacket) message.obj);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }

        @Override
        public void exit() {
            super.exit();
            mKickAlarm.cancel();
        }

        protected abstract boolean sendPacket();
        protected abstract void receivePacket(DhcpPacket packet);
        protected void timeout() {}

        protected void initTimer() {
            mTimer = FIRST_TIMEOUT_MS;
        }

        protected int jitterTimer(int baseTimer) {
            int maxJitter = baseTimer / 10;
            int jitter = mRandom.nextInt(2 * maxJitter) - maxJitter;
            return baseTimer + jitter;
        }

        protected void scheduleKick() {
            long now = SystemClock.elapsedRealtime();
            long timeout = jitterTimer(mTimer);
            long alarmTime = now + timeout;
            mKickAlarm.schedule(alarmTime);
            mTimer *= 2;
            if (mTimer > MAX_TIMEOUT_MS) {
                mTimer = MAX_TIMEOUT_MS;
            }
        }
    }

    class ObtainingConfigurationState extends LoggingState {
        @Override
        public void enter() {
            super.enter();

            // Set a timeout for retrieving network attributes operation
            sendMessageDelayed(EVENT_CONFIGURATION_TIMEOUT, IPMEMORYSTORE_TIMEOUT_MS);

            final OnNetworkAttributesRetrievedListener listener = (status, l2Key, attributes) -> {
                if (null == attributes || null == attributes.assignedV4Address) {
                    if (!status.isSuccess()) {
                        Log.e(TAG, "Error retrieving network attributes: " + status);
                    }
                    sendMessage(EVENT_CONFIGURATION_INVALID);
                    return;
                }
                sendMessage(EVENT_CONFIGURATION_OBTAINED, attributes);
            };
            mIpMemoryStore.retrieveNetworkAttributes(mL2Key, listener);
        }

        @Override
        public boolean processMessage(Message message) {
            super.processMessage(message);
            switch (message.what) {
                case EVENT_CONFIGURATION_INVALID:
                case EVENT_CONFIGURATION_TIMEOUT:
                    transitionTo(mDhcpInitState);
                    return HANDLED;

                case EVENT_CONFIGURATION_OBTAINED:
                    final long currentTime = System.currentTimeMillis();
                    NetworkAttributes attributes = (NetworkAttributes) message.obj;
                    if (DBG) {
                        Log.d(TAG, "l2key: " + mL2Key
                                + " lease address: " + attributes.assignedV4Address
                                + " lease expiry: "  + attributes.assignedV4AddressExpiry
                                + " current time: "  + currentTime);
                    }
                    if (currentTime >= attributes.assignedV4AddressExpiry) {
                        // Lease has expired.
                        transitionTo(mDhcpInitState);
                        return HANDLED;
                    }
                    mLastAssignedIpv4Address = attributes.assignedV4Address;
                    mLastAssignedIpv4AddressExpiry = attributes.assignedV4AddressExpiry;
                    transitionTo(mDhcpInitRebootState);
                    return HANDLED;

                default:
                    deferMessage(message);
                    return HANDLED;
            }
        }

        @Override
        public void exit() {
            removeMessages(EVENT_CONFIGURATION_INVALID);
            removeMessages(EVENT_CONFIGURATION_TIMEOUT);
            removeMessages(EVENT_CONFIGURATION_OBTAINED);
        }
    }

    class DhcpInitState extends PacketRetransmittingState {
        public DhcpInitState() {
            super();
        }

        @Override
        public void enter() {
            super.enter();
            startNewTransaction();
            mLastInitEnterTime = SystemClock.elapsedRealtime();
        }

        protected boolean sendPacket() {
            return sendDiscoverPacket();
        }

        protected void receivePacket(DhcpPacket packet) {
            if (!isValidPacket(packet)) return;

            // 1. received the DHCPOFFER packet, process it by following RFC2131.
            // 2. received the DHCPACK packet from DHCP Servers who support Rapid
            //    Commit option, process it by following RFC4039.
            if (packet instanceof DhcpOfferPacket) {
                mOffer = packet.toDhcpResults();
                if (mOffer != null) {
                    Log.d(TAG, "Got pending lease: " + mOffer);
                    transitionTo(mDhcpRequestingState);
                }
            } else if (packet instanceof DhcpAckPacket) {
                // If received DHCPACK packet w/o Rapid Commit option in this state,
                // just drop it and wait for the next DHCPOFFER packet or DHCPACK w/
                // Rapid Commit option.
                if (!isDhcpRapidCommitEnabled() || !packet.mRapidCommit) return;
                final DhcpResults results = packet.toDhcpResults();
                if (results != null) {
                    confirmDhcpLease(packet, results);
                    transitionTo(mConfiguringInterfaceState);
                }
            }
        }
    }

    // Not implemented. We request the first offer we receive.
    class DhcpSelectingState extends LoggingState {
    }

    class DhcpRequestingState extends PacketRetransmittingState {
        public DhcpRequestingState() {
            mTimeout = DHCP_TIMEOUT_MS / 2;
        }

        protected boolean sendPacket() {
            return sendRequestPacket(
                    INADDR_ANY,                                    // ciaddr
                    (Inet4Address) mOffer.ipAddress.getAddress(),  // DHCP_REQUESTED_IP
                    (Inet4Address) mOffer.serverAddress,           // DHCP_SERVER_IDENTIFIER
                    INADDR_BROADCAST);                             // packet destination address
        }

        protected void receivePacket(DhcpPacket packet) {
            if (!isValidPacket(packet)) return;
            if ((packet instanceof DhcpAckPacket)) {
                DhcpResults results = packet.toDhcpResults();
                if (results != null) {
                    confirmDhcpLease(packet, results);
                    transitionTo(mConfiguringInterfaceState);
                }
            } else if (packet instanceof DhcpNakPacket) {
                // TODO: Wait a while before returning into INIT state.
                Log.d(TAG, "Received NAK, returning to INIT");
                mOffer = null;
                transitionTo(mDhcpInitState);
            }
        }

        @Override
        protected void timeout() {
            // After sending REQUESTs unsuccessfully for a while, go back to init.
            transitionTo(mDhcpInitState);
        }
    }

    class DhcpHaveLeaseState extends State {
        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_EXPIRE_DHCP:
                    Log.d(TAG, "Lease expired!");
                    notifyFailure();
                    transitionTo(mDhcpInitState);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }

        @Override
        public void exit() {
            // Clear any extant alarms.
            mRenewAlarm.cancel();
            mRebindAlarm.cancel();
            mExpiryAlarm.cancel();
            clearDhcpState();
            // Tell IpManager to clear the IPv4 address. There is no need to
            // wait for confirmation since any subsequent packets are sent from
            // INADDR_ANY anyway (DISCOVER, REQUEST).
            mController.sendMessage(CMD_CLEAR_LINKADDRESS);
        }
    }

    class ConfiguringInterfaceState extends LoggingState {
        @Override
        public void enter() {
            super.enter();
            mController.sendMessage(CMD_CONFIGURE_LINKADDRESS, mDhcpLease.ipAddress);
        }

        @Override
        public boolean processMessage(Message message) {
            super.processMessage(message);
            switch (message.what) {
                case EVENT_LINKADDRESS_CONFIGURED:
                    transitionTo(mDhcpBoundState);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }
    }

    class DhcpBoundState extends LoggingState {
        @Override
        public void enter() {
            super.enter();
            if (mDhcpLease.serverAddress != null && !connectUdpSock(mDhcpLease.serverAddress)) {
                // There's likely no point in going into DhcpInitState here, we'll probably
                // just repeat the transaction, get the same IP address as before, and fail.
                //
                // NOTE: It is observed that connectUdpSock() basically never fails, due to
                // SO_BINDTODEVICE. Examining the local socket address shows it will happily
                // return an IPv4 address from another interface, or even return "0.0.0.0".
                //
                // TODO: Consider deleting this check, following testing on several kernels.
                notifyFailure();
                transitionTo(mStoppedState);
            }

            scheduleLeaseTimers();
            logTimeToBoundState();
        }

        @Override
        public void exit() {
            super.exit();
            mLastBoundExitTime = SystemClock.elapsedRealtime();
        }

        @Override
        public boolean processMessage(Message message) {
            super.processMessage(message);
            switch (message.what) {
                case CMD_RENEW_DHCP:
                    if (mRegisteredForPreDhcpNotification) {
                        transitionTo(mWaitBeforeRenewalState);
                    } else {
                        transitionTo(mDhcpRenewingState);
                    }
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }

        private void logTimeToBoundState() {
            long now = SystemClock.elapsedRealtime();
            if (mLastBoundExitTime > mLastInitEnterTime) {
                logState(EVENT_RENEWING_BOUND, (int) (now - mLastBoundExitTime));
            } else {
                logState(EVENT_INITIAL_BOUND, (int) (now - mLastInitEnterTime));
            }
        }
    }

    abstract class DhcpReacquiringState extends PacketRetransmittingState {
        protected String mLeaseMsg;

        @Override
        public void enter() {
            super.enter();
            startNewTransaction();
        }

        protected abstract Inet4Address packetDestination();

        protected boolean sendPacket() {
            return sendRequestPacket(
                    (Inet4Address) mDhcpLease.ipAddress.getAddress(),  // ciaddr
                    INADDR_ANY,                                        // DHCP_REQUESTED_IP
                    null,                                              // DHCP_SERVER_IDENTIFIER
                    packetDestination());                              // packet destination address
        }

        protected void receivePacket(DhcpPacket packet) {
            if (!isValidPacket(packet)) return;
            if ((packet instanceof DhcpAckPacket)) {
                final DhcpResults results = packet.toDhcpResults();
                if (results != null) {
                    if (!mDhcpLease.ipAddress.equals(results.ipAddress)) {
                        Log.d(TAG, "Renewed lease not for our current IP address!");
                        notifyFailure();
                        transitionTo(mDhcpInitState);
                    }
                    setDhcpLeaseExpiry(packet);
                    // Updating our notion of DhcpResults here only causes the
                    // DNS servers and routes to be updated in LinkProperties
                    // in IpManager and by any overridden relevant handlers of
                    // the registered IpManager.Callback.  IP address changes
                    // are not supported here.
                    acceptDhcpResults(results, mLeaseMsg);
                    transitionTo(mDhcpBoundState);
                }
            } else if (packet instanceof DhcpNakPacket) {
                Log.d(TAG, "Received NAK, returning to INIT");
                notifyFailure();
                transitionTo(mDhcpInitState);
            }
        }
    }

    class DhcpRenewingState extends DhcpReacquiringState {
        public DhcpRenewingState() {
            mLeaseMsg = "Renewed";
        }

        @Override
        public boolean processMessage(Message message) {
            if (super.processMessage(message) == HANDLED) {
                return HANDLED;
            }

            switch (message.what) {
                case CMD_REBIND_DHCP:
                    transitionTo(mDhcpRebindingState);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }

        @Override
        protected Inet4Address packetDestination() {
            // Not specifying a SERVER_IDENTIFIER option is a violation of RFC 2131, but...
            // http://b/25343517 . Try to make things work anyway by using broadcast renews.
            return (mDhcpLease.serverAddress != null) ?
                    mDhcpLease.serverAddress : INADDR_BROADCAST;
        }
    }

    class DhcpRebindingState extends DhcpReacquiringState {
        public DhcpRebindingState() {
            mLeaseMsg = "Rebound";
        }

        @Override
        public void enter() {
            super.enter();

            // We need to broadcast and possibly reconnect the socket to a
            // completely different server.
            closeSocketQuietly(mUdpSock);
            if (!initUdpSocket()) {
                Log.e(TAG, "Failed to recreate UDP socket");
                transitionTo(mDhcpInitState);
            }
        }

        @Override
        protected Inet4Address packetDestination() {
            return INADDR_BROADCAST;
        }
    }

    class DhcpInitRebootState extends DhcpRequestingState {
        @Override
        public void enter() {
            super.enter();
            startNewTransaction();
        }

        // RFC 2131 4.3.2 describes generated DHCPREQUEST message during
        // INIT-REBOOT state:
        // 'server identifier' MUST NOT be filled in, 'requested IP address'
        // option MUST be filled in with client's notion of its previously
        // assigned address. 'ciaddr' MUST be zero. The client is seeking to
        // verify a previously allocated, cached configuration. Server SHOULD
        // send a DHCPNAK message to the client if the 'requested IP address'
        // is incorrect, or is on the wrong network.
        @Override
        protected boolean sendPacket() {
            return sendRequestPacket(
                     INADDR_ANY,                                       // ciaddr
                     mLastAssignedIpv4Address,                         // DHCP_REQUESTED_IP
                     null,                                             // DHCP_SERVER_IDENTIFIER
                     INADDR_BROADCAST);                                // packet destination address
        }

        @Override
        public void exit() {
            mLastAssignedIpv4Address = null;
            mLastAssignedIpv4AddressExpiry = 0;
        }
    }

    class DhcpRebootingState extends LoggingState {
    }

    private void logState(String name, int durationMs) {
        final DhcpClientEvent event = new DhcpClientEvent.Builder()
                .setMsg(name)
                .setDurationMs(durationMs)
                .build();
        mMetricsLog.log(mIfaceName, event);
    }
}

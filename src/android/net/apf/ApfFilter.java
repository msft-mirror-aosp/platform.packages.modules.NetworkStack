/*
 * Copyright (C) 2024 The Android Open Source Project
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

package android.net.apf;

import static android.net.apf.ApfConstants.APF_MAX_ETH_TYPE_BLACK_LIST_LEN;
import static android.net.apf.ApfConstants.ARP_HEADER_OFFSET;
import static android.net.apf.ApfConstants.ARP_IPV4_HEADER;
import static android.net.apf.ApfConstants.ARP_OPCODE_OFFSET;
import static android.net.apf.ApfConstants.ARP_OPCODE_REPLY;
import static android.net.apf.ApfConstants.ARP_OPCODE_REQUEST;
import static android.net.apf.ApfConstants.ARP_SOURCE_IP_ADDRESS_OFFSET;
import static android.net.apf.ApfConstants.ARP_TARGET_IP_ADDRESS_OFFSET;
import static android.net.apf.ApfConstants.DHCP_CLIENT_MAC_OFFSET;
import static android.net.apf.ApfConstants.DHCP_CLIENT_PORT;
import static android.net.apf.ApfConstants.DHCP_SERVER_PORT;
import static android.net.apf.ApfConstants.DNS_HEADER_LEN;
import static android.net.apf.ApfConstants.ECHO_PORT;
import static android.net.apf.ApfConstants.ETH_DEST_ADDR_OFFSET;
import static android.net.apf.ApfConstants.ETH_ETHERTYPE_OFFSET;
import static android.net.apf.ApfConstants.ETH_HEADER_LEN;
import static android.net.apf.ApfConstants.ETH_MULTICAST_IGMP_V3_ALL_MULTICAST_ROUTERS_ADDRESS;
import static android.net.apf.ApfConstants.ETH_MULTICAST_MDNS_V4_MAC_ADDRESS;
import static android.net.apf.ApfConstants.ETH_MULTICAST_MDNS_V6_MAC_ADDRESS;
import static android.net.apf.ApfConstants.ETH_MULTICAST_MLD_V2_ALL_MULTICAST_ROUTERS_ADDRESS;
import static android.net.apf.ApfConstants.ETH_TYPE_MAX;
import static android.net.apf.ApfConstants.ETH_TYPE_MIN;
import static android.net.apf.ApfConstants.FIXED_ARP_REPLY_HEADER;
import static android.net.apf.ApfConstants.ICMP4_CHECKSUM_NO_OPTIONS_OFFSET;
import static android.net.apf.ApfConstants.ICMP4_CONTENT_NO_OPTIONS_OFFSET;
import static android.net.apf.ApfConstants.ICMP4_TYPE_NO_OPTIONS_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_4_BYTE_LIFETIME_LEN;
import static android.net.apf.ApfConstants.ICMP6_4_BYTE_LIFETIME_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_CAPTIVE_PORTAL_OPTION_TYPE;
import static android.net.apf.ApfConstants.ICMP6_CHECKSUM_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_CODE_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_CONTENT_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_DNSSL_OPTION_TYPE;
import static android.net.apf.ApfConstants.ICMP6_ECHO_REQUEST_HEADER_LEN;
import static android.net.apf.ApfConstants.ICMP6_MTU_OPTION_TYPE;
import static android.net.apf.ApfConstants.ICMP6_NS_OPTION_TYPE_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_NS_TARGET_IP_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_PREF64_OPTION_TYPE;
import static android.net.apf.ApfConstants.ICMP6_PREFIX_OPTION_PREFERRED_LIFETIME_LEN;
import static android.net.apf.ApfConstants.ICMP6_PREFIX_OPTION_TYPE;
import static android.net.apf.ApfConstants.ICMP6_PREFIX_OPTION_VALID_LIFETIME_LEN;
import static android.net.apf.ApfConstants.ICMP6_PREFIX_OPTION_VALID_LIFETIME_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_RA_CHECKSUM_LEN;
import static android.net.apf.ApfConstants.ICMP6_RA_CHECKSUM_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_RA_FLAGS_EXTENSION_OPTION_TYPE;
import static android.net.apf.ApfConstants.ICMP6_RA_OPTION_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_RA_ROUTER_LIFETIME_LEN;
import static android.net.apf.ApfConstants.ICMP6_RA_ROUTER_LIFETIME_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_RDNSS_OPTION_TYPE;
import static android.net.apf.ApfConstants.ICMP6_ROUTE_INFO_OPTION_TYPE;
import static android.net.apf.ApfConstants.ICMP6_SOURCE_LL_ADDRESS_OPTION_TYPE;
import static android.net.apf.ApfConstants.ICMP6_TYPE_OFFSET;
import static android.net.apf.ApfConstants.IGMPV2_REPORT_FROM_IPV4_OPTION_TO_IGMP_CHECKSUM;
import static android.net.apf.ApfConstants.IGMPV3_MODE_IS_EXCLUDE;
import static android.net.apf.ApfConstants.IGMP_CHECKSUM_WITH_ROUTER_ALERT_OFFSET;
import static android.net.apf.ApfConstants.IGMP_MAX_RESP_TIME_OFFSET;
import static android.net.apf.ApfConstants.IGMP_MULTICAST_ADDRESS_OFFSET;
import static android.net.apf.ApfConstants.IGMP_TYPE_REPORTS;
import static android.net.apf.ApfConstants.IPPROTO_HOPOPTS;
import static android.net.apf.ApfConstants.IPV4_ALL_HOSTS_ADDRESS_IN_LONG;
import static android.net.apf.ApfConstants.IPV4_ALL_IGMPV3_MULTICAST_ROUTERS_ADDRESS;
import static android.net.apf.ApfConstants.IPV4_ANY_HOST_ADDRESS;
import static android.net.apf.ApfConstants.IPV4_BROADCAST_ADDRESS;
import static android.net.apf.ApfConstants.IPV4_DEST_ADDR_OFFSET;
import static android.net.apf.ApfConstants.IPV4_DNS_QDCOUNT_NO_OPTIONS_OFFSET;
import static android.net.apf.ApfConstants.IPV4_FRAGMENT_MORE_FRAGS_MASK;
import static android.net.apf.ApfConstants.IPV4_FRAGMENT_OFFSET_MASK;
import static android.net.apf.ApfConstants.IPV4_FRAGMENT_OFFSET_OFFSET;
import static android.net.apf.ApfConstants.IPV4_IGMP_TYPE_QUERY;
import static android.net.apf.ApfConstants.IPV4_PROTOCOL_OFFSET;
import static android.net.apf.ApfConstants.IPV4_SRC_ADDR_OFFSET;
import static android.net.apf.ApfConstants.IPV4_ROUTER_ALERT_OPTION;
import static android.net.apf.ApfConstants.IPV4_ROUTER_ALERT_OPTION_LEN;
import static android.net.apf.ApfConstants.IPV4_TOTAL_LENGTH_OFFSET;
import static android.net.apf.ApfConstants.IPV4_UDP_DESTINATION_CHECKSUM_NO_OPTIONS_OFFSET;
import static android.net.apf.ApfConstants.IPV4_UDP_DESTINATION_PORT_NO_OPTIONS_OFFSET;
import static android.net.apf.ApfConstants.IPV4_UDP_PAYLOAD_NO_OPTIONS_OFFSET;
import static android.net.apf.ApfConstants.IPV6_ALL_NODES_ADDRESS;
import static android.net.apf.ApfConstants.IPV6_DEST_ADDR_OFFSET;
import static android.net.apf.ApfConstants.IPV6_DNS_QDCOUNT_OFFSET;
import static android.net.apf.ApfConstants.IPV6_EXT_HEADER_OFFSET;
import static android.net.apf.ApfConstants.IPV6_FLOW_LABEL_LEN;
import static android.net.apf.ApfConstants.IPV6_FLOW_LABEL_OFFSET;
import static android.net.apf.ApfConstants.IPV6_HEADER_LEN;
import static android.net.apf.ApfConstants.IPV6_HOP_LIMIT_OFFSET;
import static android.net.apf.ApfConstants.IPV6_MLD_CHECKSUM_OFFSET;
import static android.net.apf.ApfConstants.IPV6_MLD_HOPOPTS;
import static android.net.apf.ApfConstants.IPV6_MLD_MESSAGE_MIN_SIZE;
import static android.net.apf.ApfConstants.IPV6_MLD_MIN_SIZE;
import static android.net.apf.ApfConstants.IPV6_MLD_MULTICAST_ADDR_OFFSET;
import static android.net.apf.ApfConstants.IPV6_MLD_TYPE_OFFSET;
import static android.net.apf.ApfConstants.IPV6_MLD_TYPE_QUERY;
import static android.net.apf.ApfConstants.IPV6_MLD_TYPE_REPORTS;
import static android.net.apf.ApfConstants.IPV6_MLD_TYPE_V1_REPORT;
import static android.net.apf.ApfConstants.IPV6_MLD_TYPE_V2_REPORT;
import static android.net.apf.ApfConstants.IPV6_MLD_V1_MESSAGE_SIZE;
import static android.net.apf.ApfConstants.IPV6_MLD_V2_ALL_ROUTERS_MULTICAST_ADDRESS;
import static android.net.apf.ApfConstants.IPV6_MLD_V2_MULTICAST_ADDRESS_RECORD_SIZE;
import static android.net.apf.ApfConstants.IPV6_NEXT_HEADER_OFFSET;
import static android.net.apf.ApfConstants.IPV6_PAYLOAD_LEN_OFFSET;
import static android.net.apf.ApfConstants.IPV6_SOLICITED_NODES_PREFIX;
import static android.net.apf.ApfConstants.IPV6_SRC_ADDR_OFFSET;
import static android.net.apf.ApfConstants.IPV6_UDP_DESTINATION_CHECKSUM_OFFSET;
import static android.net.apf.ApfConstants.IPV6_UDP_DESTINATION_PORT_OFFSET;
import static android.net.apf.ApfConstants.IPV6_UNSPECIFIED_ADDRESS;
import static android.net.apf.ApfConstants.MLD2_MODE_IS_EXCLUDE;
import static android.net.apf.ApfConstants.TCP_HEADER_SIZE_OFFSET;
import static android.net.apf.ApfConstants.TCP_UDP_DESTINATION_PORT_OFFSET;
import static android.net.apf.ApfConstants.TCP_UDP_SOURCE_PORT_OFFSET;
import static android.net.apf.ApfCounterTracker.Counter.APF_PROGRAM_ID;
import static android.net.apf.ApfCounterTracker.Counter.APF_VERSION;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_802_3_FRAME;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_NON_IPV4;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_OTHER_HOST;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_REPLY_SPA_NO_HOST;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_REQUEST_REPLIED;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_UNKNOWN;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_V6_ONLY;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ETHERTYPE_NOT_ALLOWED;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ETHER_OUR_SRC_MAC;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ETH_BROADCAST;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_GARP_REPLY;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_BROADCAST_ADDR;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_BROADCAST_NET;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IGMP_INVALID;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IGMP_REPORT;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_ICMP_INVALID;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_KEEPALIVE_ACK;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_L2_BROADCAST;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_MULTICAST;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_NATT_KEEPALIVE;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_NON_DHCP4;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_PING_REQUEST_REPLIED;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_TCP_PORT7_UNICAST;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_ICMP6_ECHO_REQUEST_INVALID;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_ICMP6_ECHO_REQUEST_REPLIED;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_MLD_INVALID;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_MLD_REPORT;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_MLD_V1_GENERAL_QUERY_REPLIED;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_MLD_V2_GENERAL_QUERY_REPLIED;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_MULTICAST_NA;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NON_ICMP_MULTICAST;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_INVALID;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_OTHER_HOST;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_REPLIED_NON_DAD;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_ROUTER_SOLICITATION;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_MDNS;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_RA;
import static android.net.apf.ApfCounterTracker.Counter.FILTER_AGE_16384THS;
import static android.net.apf.ApfCounterTracker.Counter.FILTER_AGE_SECONDS;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_BROADCAST_REPLY;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_REQUEST;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_UNICAST_REPLY;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_DHCP;
import static android.net.apf.ApfConstants.IPv6_UDP_PAYLOAD_OFFSET;
import static android.net.apf.ApfConstants.MDNS_IPV4_ADDR;
import static android.net.apf.ApfConstants.MDNS_IPV4_ADDR_IN_LONG;
import static android.net.apf.ApfConstants.MDNS_IPV6_ADDR;
import static android.net.apf.ApfConstants.MDNS_PORT;
import static android.net.apf.ApfConstants.UDP_HEADER_LEN;
import static android.net.apf.ApfConstants.MDNS_PORT_IN_BYTES;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_ETHER_OUR_SRC_MAC;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4_FROM_DHCPV4_SERVER;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4_UNICAST;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_HOPOPTS;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_ICMP;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NON_ICMP;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_UNICAST_NON_ICMP;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_MDNS;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_NON_IP_UNICAST;
import static android.net.apf.ApfCounterTracker.Counter.TOTAL_PACKETS;
import static android.net.apf.ApfCounterTracker.getCounterValue;
import static android.net.apf.BaseApfGenerator.MemorySlot;
import static android.net.apf.BaseApfGenerator.Register.R0;
import static android.net.apf.BaseApfGenerator.Register.R1;
import static android.net.util.SocketUtils.makePacketSocketAddress;
import static android.os.PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED;
import static android.os.PowerManager.ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED;
import static android.system.OsConstants.AF_PACKET;
import static android.system.OsConstants.ETH_P_ALL;
import static android.system.OsConstants.ETH_P_ARP;
import static android.system.OsConstants.ETH_P_IP;
import static android.system.OsConstants.ETH_P_IPV6;
import static android.system.OsConstants.ICMP6_ECHO_REPLY;
import static android.system.OsConstants.ICMP_ECHO;
import static android.system.OsConstants.ICMP_ECHOREPLY;
import static android.system.OsConstants.IFA_F_TENTATIVE;
import static android.system.OsConstants.IPPROTO_ICMP;
import static android.system.OsConstants.IPPROTO_ICMPV6;
import static android.system.OsConstants.IPPROTO_TCP;
import static android.system.OsConstants.IPPROTO_UDP;
import static android.system.OsConstants.SOCK_CLOEXEC;
import static android.system.OsConstants.SOCK_NONBLOCK;
import static android.system.OsConstants.SOCK_RAW;

import static com.android.net.module.util.CollectionUtils.concatArrays;
import static com.android.net.module.util.NetworkStackConstants.ETHER_ADDR_LEN;
import static com.android.net.module.util.NetworkStackConstants.ETHER_BROADCAST;
import static com.android.net.module.util.NetworkStackConstants.ETHER_DST_ADDR_OFFSET;
import static com.android.net.module.util.NetworkStackConstants.ETHER_HEADER_LEN;
import static com.android.net.module.util.NetworkStackConstants.ETHER_SRC_ADDR_OFFSET;
import static com.android.net.module.util.NetworkStackConstants.ICMP_HEADER_LEN;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ECHO_REQUEST_TYPE;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_NA_HEADER_LEN;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ND_OPTION_SLLA;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ND_OPTION_TLLA;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ND_OPTION_TLLA_LEN;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_NEIGHBOR_ADVERTISEMENT;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_NEIGHBOR_SOLICITATION;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ROUTER_ADVERTISEMENT;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ROUTER_SOLICITATION;
import static com.android.net.module.util.NetworkStackConstants.IPV4_ADDR_ALL_HOST_MULTICAST;
import static com.android.net.module.util.NetworkStackConstants.IPV4_ADDR_LEN;
import static com.android.net.module.util.NetworkStackConstants.IPV4_HEADER_MIN_LEN;
import static com.android.net.module.util.NetworkStackConstants.IPV4_FLAG_DF;
import static com.android.net.module.util.NetworkStackConstants.IPV4_IGMP_GROUP_RECORD_SIZE;
import static com.android.net.module.util.NetworkStackConstants.IPV4_IGMP_MIN_SIZE;
import static com.android.net.module.util.NetworkStackConstants.IPV4_IGMP_TYPE_V3_REPORT;
import static com.android.net.module.util.NetworkStackConstants.IPV4_PROTOCOL_IGMP;
import static com.android.net.module.util.NetworkStackConstants.IPV6_ADDR_ALL_NODES_MULTICAST;
import static com.android.net.module.util.NetworkStackConstants.IPV6_ADDR_ANY;
import static com.android.net.module.util.NetworkStackConstants.IPV6_ADDR_LEN;
import static com.android.net.module.util.NetworkStackConstants.IPV6_ADDR_NODE_LOCAL_ALL_NODES_MULTICAST;

import android.annotation.ChecksSdkIntAtLeast;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.MacAddress;
import android.net.NattKeepalivePacketDataParcelable;
import android.net.TcpKeepalivePacketDataParcelable;
import android.net.apf.ApfCounterTracker.Counter;
import android.net.apf.BaseApfGenerator.IllegalInstructionException;
import android.net.ip.MulticastReportMonitor;
import android.net.nsd.NsdManager;
import android.os.Handler;
import android.os.PowerManager;
import android.os.SystemClock;
import android.stats.connectivity.NetworkQuirkEvent;
import android.system.ErrnoException;
import android.system.Os;
import android.text.format.DateUtils;
import android.util.ArraySet;
import android.util.Log;
import android.util.Pair;
import android.util.SparseArray;

import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.util.HexDump;
import com.android.internal.util.IndentingPrintWriter;
import com.android.internal.util.TokenBucket;
import com.android.modules.utils.build.SdkLevel;
import com.android.net.module.util.CollectionUtils;
import com.android.net.module.util.ConnectivityUtils;
import com.android.net.module.util.InterfaceParams;
import com.android.net.module.util.PacketReader;
import com.android.networkstack.metrics.ApfSessionInfoMetrics;
import com.android.networkstack.metrics.IpClientRaInfoMetrics;
import com.android.networkstack.metrics.NetworkQuirkMetrics;
import com.android.networkstack.util.NetworkStackUtils;

import java.io.FileDescriptor;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * For networks that support packet filtering via APF programs, {@code ApfFilter}
 * listens for IPv6 ICMPv6 router advertisements (RAs) and generates APF programs to
 * filter out redundant duplicate ones.
 * <p>
 * Threading model: this class is not thread-safe and can only be accessed from IpClient's
 * handler thread.
 *
 * @hide
 */
public class ApfFilter {

    /**
     * Defines the communication API between the ApfFilter and the APF interpreter
     * residing within the Wi-Fi/Ethernet firmware.
     */
    public interface IApfController {
        /**
         * Install the APF program to firmware.
         */
        boolean installPacketFilter(@NonNull byte[] filter, @NonNull String filterConfig);

        /**
         * Read the APF RAM from firmware.
         */
        void readPacketFilterRam(@NonNull String event);
    }

    // Helper class for specifying functional filter parameters.
    public static class ApfConfiguration {
        public int apfVersionSupported;
        public int apfRamSize;
        public int installableProgramSizeClamp = Integer.MAX_VALUE;
        public boolean multicastFilter;
        public boolean ieee802_3Filter;
        public int[] ethTypeBlackList;
        public int minRdnssLifetimeSec;
        public int acceptRaMinLft;
        public long minMetricsSessionDurationMs;
        public boolean hasClatInterface;
        public boolean handleArpOffload;
        public boolean handleNdOffload;
        public boolean handleMdnsOffload;
        public boolean handleIgmpOffload;
        public boolean handleMldOffload;
        public boolean handleIpv4PingOffload;
        public boolean handleIpv6PingOffload;
    }


    private class RaPacketReader extends PacketReader {
        private static final int RECEIVE_BUFFER_SIZE = 1514;
        private final int mIfIndex;

        RaPacketReader(Handler handler, int ifIndex) {
            super(handler, RECEIVE_BUFFER_SIZE);
            mIfIndex = ifIndex;
        }

        @Override
        protected FileDescriptor createFd() {
            return mDependencies.createPacketReaderSocket(mIfIndex);
        }

        @Override
        protected void handlePacket(byte[] recvbuf, int length) {
            processRa(recvbuf, length);
        }
    }

    private static final String TAG = "ApfFilter";

    private final int mApfRamSize;
    private final int mMaximumApfProgramSize;
    private final int mInstallableProgramSizeClamp;
    private final IApfController mApfController;
    private final InterfaceParams mInterfaceParams;
    private final TokenBucket mTokenBucket;

    @VisibleForTesting
    public final int mApfVersionSupported;
    @VisibleForTesting
    @NonNull
    public final byte[] mHardwareAddress;
    private final RaPacketReader mRaPacketReader;
    private final Handler mHandler;
    private boolean mMulticastFilter;
    private boolean mInDozeMode;
    private final boolean mDrop802_3Frames;
    private final int[] mEthTypeBlackList;

    private final ApfCounterTracker mApfCounterTracker = new ApfCounterTracker();
    private final long mSessionStartMs;
    private int mNumParseErrorRas = 0;
    private int mNumZeroLifetimeRas = 0;
    private int mLowestRouterLifetimeSeconds = Integer.MAX_VALUE;
    private long mLowestPioValidLifetimeSeconds = Long.MAX_VALUE;
    private long mLowestRioRouteLifetimeSeconds = Long.MAX_VALUE;
    private long mLowestRdnssLifetimeSeconds = Long.MAX_VALUE;

    // Ignore non-zero RDNSS lifetimes below this value.
    private final int mMinRdnssLifetimeSec;

    // Minimum session time for metrics, duration less than this time will not be logged.
    private final long mMinMetricsSessionDurationMs;

    // Tracks the value of /proc/sys/ipv6/conf/$iface/accept_ra_min_lft which affects router, RIO,
    // and PIO valid lifetimes.
    private final int mAcceptRaMinLft;
    private final boolean mHandleArpOffload;
    private final boolean mHandleNdOffload;
    private final boolean mHandleMdnsOffload;
    private final boolean mHandleIgmpOffload;
    private final boolean mHandleMldOffload;
    private final boolean mHandleIpv4PingOffload;
    private final boolean mHandleIpv6PingOffload;

    private final NetworkQuirkMetrics mNetworkQuirkMetrics;
    private final IpClientRaInfoMetrics mIpClientRaInfoMetrics;
    private final ApfSessionInfoMetrics mApfSessionInfoMetrics;
    private final NsdManager mNsdManager;
    private final MulticastReportMonitor mMulticastReportMonitor;
    private final ApfMdnsOffloadEngine mApfMdnsOffloadEngine;
    private final List<MdnsOffloadRule> mOffloadRules = new ArrayList<>();

    private static boolean isDeviceIdleModeChangedAction(Intent intent) {
        return ACTION_DEVICE_IDLE_MODE_CHANGED.equals(intent.getAction());
    }

    private boolean isDeviceLightIdleModeChangedAction(Intent intent) {
        // The ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED only exist since T. For lower platform version,
        // the check should return false. The explicit SDK check is needed to make linter happy
        // about accessing ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED in this function.
        if (!SdkLevel.isAtLeastT()) {
            return false;
        }
        return ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED.equals(intent.getAction());
    }

    private boolean isDeviceLightIdleMode(@NonNull PowerManager powerManager) {
        // The powerManager.isDeviceLightIdleMode() only exist since T. For lower platform version,
        // the check should return false. The explicit SDK check is needed to make linter happy
        // about accessing powerManager.isDeviceLightIdleMode() in this function.
        if (!SdkLevel.isAtLeastT()) {
            return false;
        }

        return powerManager.isDeviceLightIdleMode();
    }

    // Detects doze mode state transitions.
    private final BroadcastReceiver mDeviceIdleReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            mHandler.post(() -> {
                if (mIsApfShutdown) return;
                final PowerManager powerManager = context.getSystemService(PowerManager.class);
                if (isDeviceIdleModeChangedAction(intent)
                        || isDeviceLightIdleModeChangedAction(intent)) {
                    final boolean deviceIdle = powerManager.isDeviceIdleMode()
                            || isDeviceLightIdleMode(powerManager);
                    setDozeMode(deviceIdle);
                }
            });
        }
    };

    private boolean mIsApfShutdown;

    // Our IPv4 address, if we have just one, otherwise null.
    private byte[] mIPv4Address;
    // The subnet prefix length of our IPv4 network. Only valid if mIPv4Address is not null.
    private int mIPv4PrefixLength;

    // Our IPv6 non-tentative addresses
    private Set<Inet6Address> mIPv6NonTentativeAddresses = new ArraySet<>();

    // Our tentative IPv6 addresses
    private Set<Inet6Address> mIPv6TentativeAddresses = new ArraySet<>();

    // Our link-local IPv6 address
    private Inet6Address mIPv6LinkLocalAddress;

    // Our joined IPv4 multicast addresses
    @VisibleForTesting
    final Set<Inet4Address> mIPv4MulticastAddresses = new ArraySet<>();

    // Our joined IPv4 multicast address exclude all all host multicast (224.0.0.1)
    @VisibleForTesting
    final Set<Inet4Address> mIPv4McastAddrsExcludeAllHost = new ArraySet<>();

    // Our joined IPv6 multicast addresses
    @VisibleForTesting
    final Set<Inet6Address> mIPv6MulticastAddresses = new ArraySet<>();

    // Our joined IPv6 multicast address exclude ff02::1, ff01::1
    @VisibleForTesting
    final Set<Inet6Address> mIPv6McastAddrsExcludeAllHost = new ArraySet<>();

    // Whether CLAT is enabled.
    private boolean mHasClat;

    // mIsRunning is reflects the state of the ApfFilter during integration tests. ApfFilter can be
    // paused using "adb shell cmd apf <iface> <cmd>" commands. A paused ApfFilter will not install
    // any new programs, but otherwise operates normally.
    private volatile boolean mIsRunning = true;

    private final Dependencies mDependencies;

    public ApfFilter(Handler handler, Context context, ApfConfiguration config,
            InterfaceParams ifParams, IApfController apfController,
            NetworkQuirkMetrics networkQuirkMetrics) {
        this(handler, context, config, ifParams, apfController, networkQuirkMetrics,
                new Dependencies(context));
    }

    private void maybeCleanUpApfRam() {
        // Clear the APF memory to reset all counters upon connecting to the first AP
        // in an SSID. This is limited to APFv3 devices because this large write triggers
        // a crash on some older devices (b/78905546).
        if (hasDataAccess(mApfVersionSupported)) {
            installPacketFilter(new byte[mApfRamSize], getApfConfigMessage() + " (cleanup)");
        }
    }

    @VisibleForTesting
    public ApfFilter(Handler handler, Context context, ApfConfiguration config,
            InterfaceParams ifParams, IApfController apfController,
            NetworkQuirkMetrics networkQuirkMetrics, Dependencies dependencies) {
        mHandler = handler;
        mApfVersionSupported = config.apfVersionSupported;
        mApfRamSize = config.apfRamSize;
        mInstallableProgramSizeClamp = config.installableProgramSizeClamp;
        int maximumApfProgramSize = mApfRamSize;
        if (hasDataAccess(mApfVersionSupported)) {
            // Reserve space for the counters.
            maximumApfProgramSize -= Counter.totalSize();
        }
        // Prevent generating (and thus installing) larger programs
        if (maximumApfProgramSize > mInstallableProgramSizeClamp) {
            maximumApfProgramSize = mInstallableProgramSizeClamp;
        }
        mMaximumApfProgramSize = Math.max(0, maximumApfProgramSize);
        mApfController = apfController;
        mInterfaceParams = ifParams;
        mMulticastFilter = config.multicastFilter;
        mDrop802_3Frames = config.ieee802_3Filter;
        mMinRdnssLifetimeSec = config.minRdnssLifetimeSec;
        mAcceptRaMinLft = config.acceptRaMinLft;
        mHandleArpOffload = config.handleArpOffload;
        mHandleNdOffload = config.handleNdOffload;
        mHandleMdnsOffload = config.handleMdnsOffload;
        mHandleIgmpOffload = config.handleIgmpOffload;
        mHandleMldOffload = config.handleMldOffload;
        mHandleIpv4PingOffload = config.handleIpv4PingOffload;
        mHandleIpv6PingOffload = config.handleIpv6PingOffload;
        mDependencies = dependencies;
        mNetworkQuirkMetrics = networkQuirkMetrics;
        mIpClientRaInfoMetrics = dependencies.getIpClientRaInfoMetrics();
        mApfSessionInfoMetrics = dependencies.getApfSessionInfoMetrics();
        mSessionStartMs = dependencies.elapsedRealtime();
        mMinMetricsSessionDurationMs = config.minMetricsSessionDurationMs;
        mHasClat = config.hasClatInterface;

        mIsApfShutdown = false;

        // Now fill the black list from the passed array
        mEthTypeBlackList = filterEthTypeBlackList(config.ethTypeBlackList);

        // TokenBucket for rate limiting filter installation. APF filtering relies on the filter
        // always being up-to-date and APF bytecode being in sync with userspace. The TokenBucket
        // merely prevents illconfigured / abusive networks from impacting the system, so it does
        // not need to be very restrictive.
        // The TokenBucket starts with its full capacity of 20 tokens (= 20 filter updates). A new
        // token is generated every 3 seconds limiting the filter update rate to at most once every
        // 3 seconds.
        mTokenBucket = new TokenBucket(3_000 /* deltaMs */, 20 /* capacity */, 20 /* tokens */);

        mHardwareAddress = mInterfaceParams.macAddr.toByteArray();
        // TODO: ApfFilter should not generate programs until IpClient sends provisioning success.
        maybeCleanUpApfRam();
        // Install basic filters
        installNewProgram();

        mRaPacketReader = new RaPacketReader(mHandler, mInterfaceParams.index);
        // The class constructor must be called from the IpClient's handler thread
        if (!mRaPacketReader.start()) {
            Log.wtf(TAG, "Failed to start RaPacketReader");
        }

        mMulticastReportMonitor = createMulticastReportMonitor();
        if (mMulticastReportMonitor != null) {
            mMulticastReportMonitor.start();
        }

        // Listen for doze-mode transition changes to enable/disable the IPv6 multicast filter.
        mDependencies.addDeviceIdleReceiver(mDeviceIdleReceiver);

        mNsdManager = context.getSystemService(NsdManager.class);
        if (enableOffloadEngineRegistration()) {
            mApfMdnsOffloadEngine = new ApfMdnsOffloadEngine(mInterfaceParams.name, mHandler,
                    mNsdManager,
                    allRules -> {
                        mOffloadRules.clear();
                        mOffloadRules.addAll(allRules);
                        installNewProgram();
                    });
            mApfMdnsOffloadEngine.registerOffloadEngine();
        } else {
            mApfMdnsOffloadEngine = null;
        }

        mIPv4MulticastAddresses.addAll(
                mDependencies.getIPv4MulticastAddresses(mInterfaceParams.name));
        mIPv4McastAddrsExcludeAllHost.addAll(mIPv4MulticastAddresses);
        mIPv4McastAddrsExcludeAllHost.remove((IPV4_ADDR_ALL_HOST_MULTICAST));

        mIPv6MulticastAddresses.addAll(
                mDependencies.getIPv6MulticastAddresses(mInterfaceParams.name));
        mIPv6McastAddrsExcludeAllHost.addAll(mIPv6MulticastAddresses);
        mIPv6McastAddrsExcludeAllHost.remove(IPV6_ADDR_ALL_NODES_MULTICAST);
        mIPv6McastAddrsExcludeAllHost.remove(IPV6_ADDR_NODE_LOCAL_ALL_NODES_MULTICAST);
    }

    /**
     * Dependencies class for testing.
     */
    @VisibleForTesting
    public static class Dependencies {
        private final Context mContext;
        public Dependencies(final Context context) {
            mContext = context;
        }

        /**
         * Create a socket to read RAs.
         */
        @Nullable
        public FileDescriptor createPacketReaderSocket(int ifIndex) {
            FileDescriptor socket;
            try {
                socket = Os.socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
                NetworkStackUtils.attachRaFilter(socket);
                SocketAddress addr = makePacketSocketAddress(ETH_P_IPV6, ifIndex);
                Os.bind(socket, addr);
            } catch (SocketException | ErrnoException e) {
                Log.wtf(TAG, "Error starting filter", e);
                return null;
            }
            return socket;
        }

        /**
         * Create a socket to read egress IGMPv2/v3 reports.
         */
        @Nullable
        public FileDescriptor createEgressIgmpReportsReaderSocket(int ifIndex) {
            FileDescriptor socket;
            try {
                socket = Os.socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, 0);
                NetworkStackUtils.attachEgressIgmpReportFilter(socket);
                Os.bind(socket, makePacketSocketAddress(ETH_P_ALL, ifIndex));
            } catch (SocketException | ErrnoException e) {
                Log.wtf(TAG, "Error starting filter", e);
                return null;
            }

            return socket;
        }

        /**
         * Create a socket to read egress IGMPv2/v3, MLDv1/v2 reports.
         */
        @Nullable
        public FileDescriptor createEgressMulticastReportsReaderSocket(int ifIndex) {
            FileDescriptor socket;
            try {
                socket = Os.socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, 0);
                NetworkStackUtils.attachEgressMulticastReportFilter(socket);
                Os.bind(socket, makePacketSocketAddress(ETH_P_ALL, ifIndex));
            } catch (SocketException | ErrnoException e) {
                Log.wtf(TAG, "Error starting filter", e);
                return null;
            }

            return socket;
        }

        /**
         * Get elapsedRealtime.
         */
        public long elapsedRealtime() {
            return SystemClock.elapsedRealtime();
        }

        /** Add receiver for detecting doze mode change */
        public void addDeviceIdleReceiver(@NonNull final BroadcastReceiver receiver) {
            final IntentFilter intentFilter = new IntentFilter(ACTION_DEVICE_IDLE_MODE_CHANGED);
            if (SdkLevel.isAtLeastT()) {
                intentFilter.addAction(ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED);
            }
            mContext.registerReceiver(receiver, intentFilter);
        }

        /** Remove broadcast receiver. */
        public void removeBroadcastReceiver(@NonNull final BroadcastReceiver receiver) {
            mContext.unregisterReceiver(receiver);
        }

        /**
         * Get a ApfSessionInfoMetrics instance.
         */
        public ApfSessionInfoMetrics getApfSessionInfoMetrics() {
            return new ApfSessionInfoMetrics();
        }

        /**
         * Get a IpClientRaInfoMetrics instance.
         */
        public IpClientRaInfoMetrics getIpClientRaInfoMetrics() {
            return new IpClientRaInfoMetrics();
        }

        /**
         * Callback to be called when an ApfFilter instance is created.
         *
         * This method is designed to be overridden in test classes to collect created ApfFilter
         * instances.
         */
        public void onApfFilterCreated(@NonNull ApfFilter apfFilter) {
        }

        /**
         * Callback to be called when a ReceiveThread instance is created.
         *
         * This method is designed for overriding in test classes to collect created threads and
         * waits for the termination.
         */
        public void onThreadCreated(@NonNull Thread thread) {
        }

        /**
         * Loads the existing IPv6 anycast addresses from the file `/proc/net/anycast6`.
         */
        public List<byte[]> getAnycast6Addresses(@NonNull String ifname) {
            final List<Inet6Address> anycast6Addresses =
                    ProcfsParsingUtils.getAnycast6Addresses(ifname);
            final List<byte[]> addresses = new ArrayList<>();
            for (Inet6Address addr : anycast6Addresses) {
                addresses.add(addr.getAddress());
            }

            return addresses;
        }

        /**
         * Loads the existing Ethernet multicast addresses from the file
         * `/proc/net/dev_mcast`.
         */
        public List<byte[]> getEtherMulticastAddresses(@NonNull String ifname) {
            final List<MacAddress> etherAddresses =
                    ProcfsParsingUtils.getEtherMulticastAddresses(ifname);
            final List<byte[]> addresses = new ArrayList<>();
            for (MacAddress addr : etherAddresses) {
                addresses.add(addr.toByteArray());
            }

            return addresses;
        }

        /**
         * Loads the existing ND traffic class for the specific interface from the file
         * /proc/sys/net/ipv6/conf/{ifname}/ndisc_tclass.
         *
         * If the file does not exist or the interface is not found,
         * the function returns 0..255, 0 as default ND traffic class.
         */
        public int getNdTrafficClass(@NonNull String ifname) {
            return ProcfsParsingUtils.getNdTrafficClass(ifname);
        }

        /**
         * Returns the default TTL value for IPv4 packets from '/proc/sys/net/ipv4/ip_default_ttl'.
         */
        public int getIpv4DefaultTtl() {
            return ProcfsParsingUtils.getIpv4DefaultTtl();
        }

        /**
         * Returns the default HopLimit value for IPv6 packets.
         */
        public int getIpv6DefaultHopLimit(@NonNull String ifname) {
            return ProcfsParsingUtils.getIpv6DefaultHopLimit(ifname);
        }

        /**
         * Loads the existing IPv4 multicast addresses from the file
         * `/proc/net/igmp`.
         */
        public List<Inet4Address> getIPv4MulticastAddresses(@NonNull String ifname) {
            return ProcfsParsingUtils.getIPv4MulticastAddresses(ifname);
        }

        /**
         * Loads the existing IPv6 multicast addresses from the file `/proc/net/igmp6`.
         */
        public List<Inet6Address> getIPv6MulticastAddresses(@NonNull String ifname) {
            return ProcfsParsingUtils.getIpv6MulticastAddresses(ifname);
        }
    }

    public IApfController getApfController() {
        return mApfController;
    }

    public String setDataSnapshot(byte[] data) {
        mDataSnapshot = data;
        if (mIsRunning) {
            mApfCounterTracker.updateCountersFromData(data);
        }
        return mApfCounterTracker.getCounters().toString();
    }

    private MulticastReportMonitor createMulticastReportMonitor() {
        FileDescriptor socketFd = null;

        // Check if MLD report monitor is enabled first, it includes the IGMP report monitor.
        if (enableMldReportsMonitor()) {
            socketFd =
                mDependencies.createEgressMulticastReportsReaderSocket(mInterfaceParams.index);
        } else if (enableIgmpReportsMonitor()) {
            socketFd =
                mDependencies.createEgressIgmpReportsReaderSocket(mInterfaceParams.index);
        }

        return socketFd != null ? new MulticastReportMonitor(
                mHandler,
                mInterfaceParams,
                this::updateMulticastAddrs,
                socketFd
        ) : null;
    }

    private void log(String s) {
        Log.d(TAG, "(" + mInterfaceParams.name + "): " + s);
    }

    private static int[] filterEthTypeBlackList(int[] ethTypeBlackList) {
        ArrayList<Integer> bl = new ArrayList<>();

        for (int p : ethTypeBlackList) {
            // Check if the protocol is a valid ether type
            if ((p < ETH_TYPE_MIN) || (p > ETH_TYPE_MAX)) {
                continue;
            }

            // Check if the protocol is not repeated in the passed array
            if (bl.contains(p)) {
                continue;
            }

            // Check if list reach its max size
            if (bl.size() == APF_MAX_ETH_TYPE_BLACK_LIST_LEN) {
                Log.w(TAG, "Passed EthType Black List size too large (" + bl.size() +
                        ") using top " + APF_MAX_ETH_TYPE_BLACK_LIST_LEN + " protocols");
                break;
            }

            // Now add the protocol to the list
            bl.add(p);
        }

        return bl.stream().mapToInt(Integer::intValue).toArray();
    }

    // Returns seconds since device boot.
    private int secondsSinceBoot() {
        return (int) (mDependencies.elapsedRealtime() / DateUtils.SECOND_IN_MILLIS);
    }

    public static class InvalidRaException extends Exception {
        public InvalidRaException(String m) {
            super(m);
        }
    }

    /**
     *  Class to keep track of a section in a packet.
     */
    private static class PacketSection {
        public enum Type {
            MATCH,     // A field that should be matched (e.g., the router IP address).
            LIFETIME,  // A lifetime. Not matched, and counts toward minimum RA lifetime if >= min.
        }

        /** The type of section. */
        public final Type type;
        /** Offset into the packet at which this section begins. */
        public final int start;
        /** Length of this section in bytes. */
        public final int length;
        /** If this is a lifetime, the lifetime value. */
        public final long lifetime;
        /** If this is a lifetime, the value below which the lifetime is ignored */
        public final int min;

        PacketSection(int start, int length, Type type, long lifetime, int min) {
            this.start = start;

            if (type == Type.LIFETIME && length != 2 && length != 4) {
                throw new IllegalArgumentException("LIFETIME section length must be 2 or 4 bytes");
            }
            this.length = length;
            this.type = type;

            if (type == Type.MATCH && (lifetime != 0 || min != 0)) {
                throw new IllegalArgumentException("lifetime, min must be 0 for MATCH sections");
            }
            this.lifetime = lifetime;

            // It has already been asserted that min is 0 for MATCH sections.
            if (min < 0) {
                throw new IllegalArgumentException("min must be >= 0 for LIFETIME sections");
            }
            this.min = min;
        }

        public String toString() {
            if (type == Type.LIFETIME) {
                return String.format("%s: (%d, %d) %d %d", type, start, length, lifetime, min);
            } else {
                return String.format("%s: (%d, %d)", type, start, length);
            }
        }
    }

    // A class to hold information about an RA.
    @VisibleForTesting
    public class Ra {
        // Note: mPacket's position() cannot be assumed to be reset.
        private final ByteBuffer mPacket;

        // List of sections in the packet.
        private final ArrayList<PacketSection> mPacketSections = new ArrayList<>();

        // Router lifetime in packet
        private final int mRouterLifetime;
        // Minimum valid lifetime of PIOs in packet, Long.MAX_VALUE means not seen.
        private final long mMinPioValidLifetime;
        // Minimum route lifetime of RIOs in packet, Long.MAX_VALUE means not seen.
        private final long mMinRioRouteLifetime;
        // Minimum lifetime of RDNSSs in packet, Long.MAX_VALUE means not seen.
        private final long mMinRdnssLifetime;
        // The time in seconds in which some of the information contained in this RA expires.
        private final int mExpirationTime;
        // When the packet was last captured, in seconds since Unix Epoch
        private final int mLastSeen;

        // For debugging only. Offsets into the packet where PIOs are.
        private final ArrayList<Integer> mPrefixOptionOffsets = new ArrayList<>();

        // For debugging only. Offsets into the packet where RDNSS options are.
        private final ArrayList<Integer> mRdnssOptionOffsets = new ArrayList<>();

        // For debugging only. Offsets into the packet where RIO options are.
        private final ArrayList<Integer> mRioOptionOffsets = new ArrayList<>();

        // For debugging only. Returns the hex representation of the last matching packet.
        String getLastMatchingPacket() {
            return HexDump.toHexString(mPacket.array(), 0, mPacket.capacity(),
                    false /* lowercase */);
        }

        // For debugging only. Returns the string representation of the IPv6 address starting at
        // position pos in the packet.
        private String IPv6AddresstoString(int pos) {
            try {
                byte[] array = mPacket.array();
                // Can't just call copyOfRange() and see if it throws, because if it reads past the
                // end it pads with zeros instead of throwing.
                if (pos < 0 || pos + 16 > array.length || pos + 16 < pos) {
                    return "???";
                }
                byte[] addressBytes = Arrays.copyOfRange(array, pos, pos + 16);
                InetAddress address = InetAddress.getByAddress(addressBytes);
                return address.getHostAddress();
            } catch (UnsupportedOperationException e) {
                // array() failed. Cannot happen, mPacket is array-backed and read-write.
                return "???";
            } catch (ClassCastException|UnknownHostException e) {
                // Cannot happen.
                return "???";
            }
        }

        // Can't be static because it's in a non-static inner class.
        // TODO: Make this static once RA is its own class.
        private void prefixOptionToString(StringBuffer sb, int offset) {
            String prefix = IPv6AddresstoString(offset + 16);
            int length = getUint8(mPacket, offset + 2);
            long valid = getUint32(mPacket, offset + 4);
            long preferred = getUint32(mPacket, offset + 8);
            sb.append(String.format("%s/%d %ds/%ds ", prefix, length, valid, preferred));
        }

        private void rdnssOptionToString(StringBuffer sb, int offset) {
            int optLen = getUint8(mPacket, offset + 1) * 8;
            if (optLen < 24) return;  // Malformed or empty.
            long lifetime = getUint32(mPacket, offset + 4);
            int numServers = (optLen - 8) / 16;
            sb.append("DNS ").append(lifetime).append("s");
            for (int server = 0; server < numServers; server++) {
                sb.append(" ").append(IPv6AddresstoString(offset + 8 + 16 * server));
            }
            sb.append(" ");
        }

        private void rioOptionToString(StringBuffer sb, int offset) {
            int optLen = getUint8(mPacket, offset + 1) * 8;
            if (optLen < 8 || optLen > 24) return;  // Malformed or empty.
            int prefixLen = getUint8(mPacket, offset + 2);
            long lifetime = getUint32(mPacket, offset + 4);

            // This read is variable length because the prefix can be 0, 8 or 16 bytes long.
            // We can't use any of the ByteBuffer#get methods here because they all start reading
            // from the buffer's current position.
            byte[] prefix = new byte[IPV6_ADDR_LEN];
            System.arraycopy(mPacket.array(), offset + 8, prefix, 0, optLen - 8);
            sb.append("RIO ").append(lifetime).append("s ");
            try {
                InetAddress address = InetAddress.getByAddress(prefix);
                sb.append(address.getHostAddress());
            } catch (UnknownHostException impossible) {
                sb.append("???");
            }
            sb.append("/").append(prefixLen).append(" ");
        }

        public String toString() {
            try {
                StringBuffer sb = new StringBuffer();
                sb.append(String.format("RA %s -> %s %ds ",
                        IPv6AddresstoString(IPV6_SRC_ADDR_OFFSET),
                        IPv6AddresstoString(IPV6_DEST_ADDR_OFFSET),
                        getUint16(mPacket, ICMP6_RA_ROUTER_LIFETIME_OFFSET)));
                for (int i: mPrefixOptionOffsets) {
                    prefixOptionToString(sb, i);
                }
                for (int i: mRdnssOptionOffsets) {
                    rdnssOptionToString(sb, i);
                }
                for (int i: mRioOptionOffsets) {
                    rioOptionToString(sb, i);
                }
                return sb.toString();
            } catch (BufferUnderflowException|IndexOutOfBoundsException e) {
                return "<Malformed RA>";
            }
        }

        /**
         * Add a packet section that should be matched, starting from the current position.
         * @param length the length of the section
         */
        private void addMatchSection(int length) {
            // Don't generate JNEBS instruction for 0 bytes as they will fail the
            // ASSERT_FORWARD_IN_PROGRAM(pc + cmp_imm - 1) check (where cmp_imm is
            // the number of bytes to compare) and immediately pass the packet.
            // The code does not attempt to generate such matches, but add a safety
            // check to prevent doing so in the presence of bugs or malformed or
            // truncated packets.
            if (length == 0) return;

            // we need to add a MATCH section 'from, length, MATCH, 0, 0'
            int from = mPacket.position();

            // if possible try to increase the length of the previous match section
            int lastIdx = mPacketSections.size() - 1;
            if (lastIdx >= 0) {  // there had to be a previous section
                PacketSection prev = mPacketSections.get(lastIdx);
                if (prev.type == PacketSection.Type.MATCH) {  // of type match
                    if (prev.start + prev.length == from) {  // ending where we start
                        from -= prev.length;
                        length += prev.length;
                        mPacketSections.remove(lastIdx);
                    }
                }
            }

            mPacketSections.add(new PacketSection(from, length, PacketSection.Type.MATCH, 0, 0));
            mPacket.position(from + length);
        }

        /**
         * Add a packet section that should be matched, starting from the current position.
         * @param end the offset in the packet before which the section ends
         */
        private void addMatchUntil(int end) {
            addMatchSection(end - mPacket.position());
        }

        /**
         * Add a packet section that should be ignored, starting from the current position.
         * @param length the length of the section in bytes
         */
        private void addIgnoreSection(int length) {
            mPacket.position(mPacket.position() + length);
        }

        /**
         * Add a packet section that represents a lifetime, starting from the current position.
         * @param length the length of the section in bytes
         * @param lifetime the lifetime
         * @param min the minimum acceptable lifetime
         */
        private void addLifetimeSection(int length, long lifetime, int min) {
            mPacketSections.add(
                    new PacketSection(mPacket.position(), length, PacketSection.Type.LIFETIME,
                            lifetime, min));
            mPacket.position(mPacket.position() + length);
        }

        /**
         * Adds packet sections for an RA option with a 4-byte lifetime 4 bytes into the option
         * @param optionLength the length of the option in bytes
         * @param min the minimum acceptable lifetime
         * @param isRdnss true iff this is an RDNSS option
         */
        private long add4ByteLifetimeOption(int optionLength, int min, boolean isRdnss) {
            if (isRdnss) {
                addMatchSection(ICMP6_4_BYTE_LIFETIME_OFFSET - 2);
                addIgnoreSection(2);  // reserved, but observed non-zero
            } else {
                addMatchSection(ICMP6_4_BYTE_LIFETIME_OFFSET);
            }
            final long lifetime = getUint32(mPacket, mPacket.position());
            addLifetimeSection(ICMP6_4_BYTE_LIFETIME_LEN, lifetime, min);
            addMatchSection(optionLength - ICMP6_4_BYTE_LIFETIME_OFFSET
                    - ICMP6_4_BYTE_LIFETIME_LEN);
            return lifetime;
        }

        /**
         * Return the router lifetime of the RA
         */
        public int routerLifetime() {
            return mRouterLifetime;
        }

        /**
         * Return the minimum valid lifetime in PIOs
         */
        public long minPioValidLifetime() {
            return mMinPioValidLifetime;
        }

        /**
         * Return the minimum route lifetime in RIOs
         */
        public long minRioRouteLifetime() {
            return mMinRioRouteLifetime;
        }

        /**
         * Return the minimum lifetime in RDNSSs
         */
        public long minRdnssLifetime() {
            return mMinRdnssLifetime;
        }

        // Note that this parses RA and may throw InvalidRaException (from
        // Buffer.position(int) or due to an invalid-length option) or IndexOutOfBoundsException
        // (from ByteBuffer.get(int) ) if parsing encounters something non-compliant with
        // specifications.
        @VisibleForTesting
        public Ra(byte[] packet, int length) throws InvalidRaException {
            if (length < ICMP6_RA_OPTION_OFFSET) {
                throw new InvalidRaException("Not an ICMP6 router advertisement: too short");
            }

            mPacket = ByteBuffer.wrap(Arrays.copyOf(packet, length));
            mLastSeen = secondsSinceBoot();

            // Check packet in case a packet arrives before we attach RA filter
            // to our packet socket. b/29586253
            if (getUint16(mPacket, ETH_ETHERTYPE_OFFSET) != ETH_P_IPV6 ||
                    getUint8(mPacket, IPV6_NEXT_HEADER_OFFSET) != IPPROTO_ICMPV6 ||
                    getUint8(mPacket, ICMP6_TYPE_OFFSET) != ICMPV6_ROUTER_ADVERTISEMENT) {
                throw new InvalidRaException("Not an ICMP6 router advertisement");
            }

            // Ignore destination MAC address.
            addIgnoreSection(6 /* Size of MAC address */);

            // Ignore the flow label and low 4 bits of traffic class.
            addMatchUntil(IPV6_FLOW_LABEL_OFFSET);
            addIgnoreSection(IPV6_FLOW_LABEL_LEN);

            // Ignore IPv6 destination address.
            addMatchUntil(IPV6_DEST_ADDR_OFFSET);
            addIgnoreSection(IPV6_ADDR_LEN);

            // Ignore checksum.
            addMatchUntil(ICMP6_RA_CHECKSUM_OFFSET);
            addIgnoreSection(ICMP6_RA_CHECKSUM_LEN);

            // Parse router lifetime
            addMatchUntil(ICMP6_RA_ROUTER_LIFETIME_OFFSET);
            mRouterLifetime = getUint16(mPacket, ICMP6_RA_ROUTER_LIFETIME_OFFSET);
            addLifetimeSection(ICMP6_RA_ROUTER_LIFETIME_LEN, mRouterLifetime, mAcceptRaMinLft);
            if (mRouterLifetime == 0) mNumZeroLifetimeRas++;

            // Add remaining fields (reachable time and retransmission timer) to match section.
            addMatchUntil(ICMP6_RA_OPTION_OFFSET);

            long minPioValidLifetime = Long.MAX_VALUE;
            long minRioRouteLifetime = Long.MAX_VALUE;
            long minRdnssLifetime = Long.MAX_VALUE;

            while (mPacket.hasRemaining()) {
                final int position = mPacket.position();
                final int optionType = getUint8(mPacket, position);
                final int optionLength = getUint8(mPacket, position + 1) * 8;
                if (optionLength <= 0) {
                    throw new InvalidRaException(String.format(
                        "Invalid option length opt=%d len=%d", optionType, optionLength));
                }

                long lifetime;
                switch (optionType) {
                    case ICMP6_PREFIX_OPTION_TYPE:
                        mPrefixOptionOffsets.add(position);

                        // Parse valid lifetime
                        addMatchSection(ICMP6_PREFIX_OPTION_VALID_LIFETIME_OFFSET);
                        lifetime = getUint32(mPacket, mPacket.position());
                        addLifetimeSection(ICMP6_PREFIX_OPTION_VALID_LIFETIME_LEN,
                                lifetime, mAcceptRaMinLft);
                        minPioValidLifetime = getMinForPositiveValue(
                                minPioValidLifetime, lifetime);
                        if (lifetime == 0) mNumZeroLifetimeRas++;

                        // Parse preferred lifetime
                        lifetime = getUint32(mPacket, mPacket.position());
                        // The PIO preferred lifetime is not affected by accept_ra_min_lft and
                        // therefore does not have a minimum.
                        addLifetimeSection(ICMP6_PREFIX_OPTION_PREFERRED_LIFETIME_LEN,
                                lifetime, 0 /* min lifetime */);

                        addMatchSection(4);       // Reserved bytes
                        addMatchSection(IPV6_ADDR_LEN);  // The prefix itself
                        break;
                    // These three options have the same lifetime offset and size, and
                    // are processed with the same specialized add4ByteLifetimeOption:
                    case ICMP6_RDNSS_OPTION_TYPE:
                        mRdnssOptionOffsets.add(position);
                        lifetime = add4ByteLifetimeOption(optionLength, mMinRdnssLifetimeSec, true);
                        minRdnssLifetime = getMinForPositiveValue(minRdnssLifetime, lifetime);
                        if (lifetime == 0) mNumZeroLifetimeRas++;
                        break;
                    case ICMP6_ROUTE_INFO_OPTION_TYPE:
                        mRioOptionOffsets.add(position);
                        lifetime = add4ByteLifetimeOption(optionLength, mAcceptRaMinLft, false);
                        minRioRouteLifetime = getMinForPositiveValue(
                                minRioRouteLifetime, lifetime);
                        if (lifetime == 0) mNumZeroLifetimeRas++;
                        break;
                    case ICMP6_SOURCE_LL_ADDRESS_OPTION_TYPE:
                    case ICMP6_MTU_OPTION_TYPE:
                    case ICMP6_PREF64_OPTION_TYPE:
                    case ICMP6_RA_FLAGS_EXTENSION_OPTION_TYPE:
                        addMatchSection(optionLength);
                        break;
                    case ICMP6_CAPTIVE_PORTAL_OPTION_TYPE: // unlikely to ever change.
                    case ICMP6_DNSSL_OPTION_TYPE: // currently unsupported in userspace.
                    default:
                        // RFC4861 section 4.2 dictates we ignore unknown options for forwards
                        // compatibility.
                        // However, make sure the option's type and length match.
                        addMatchSection(2); // option type & length
                        // optionLength is guaranteed to be >= 8.
                        addIgnoreSection(optionLength - 2);
                        break;
                }
            }

            mMinPioValidLifetime = minPioValidLifetime;
            mMinRioRouteLifetime = minRioRouteLifetime;
            mMinRdnssLifetime = minRdnssLifetime;
            mExpirationTime = getExpirationTime();
        }

        public enum MatchType {
            NO_MATCH, // the RAs do not match
            MATCH_PASS, // the RAS match, and the APF program would pass.
            MATCH_DROP, // the RAs match, but the APF program would drop.
        }

        // Considering only the MATCH sections, does {@code packet} match this RA?
        MatchType matches(Ra newRa) {
            // Does their size match?
            if (newRa.mPacket.capacity() != mPacket.capacity()) return MatchType.NO_MATCH;

            // If the filter has expired, it cannot match the new RA.
            if (getRemainingFilterLft(secondsSinceBoot()) <= 0) return MatchType.NO_MATCH;

            // Check if all MATCH sections are byte-identical.
            final byte[] newPacket = newRa.mPacket.array();
            final byte[] oldPacket = mPacket.array();
            for (PacketSection section : mPacketSections) {
                if (section.type != PacketSection.Type.MATCH) continue;
                for (int i = section.start; i < (section.start + section.length); i++) {
                    if (newPacket[i] != oldPacket[i]) return MatchType.NO_MATCH;
                }
            }

            // Apply APF lifetime matching to LIFETIME sections and decide whether a packet should
            // be processed (MATCH_PASS) or ignored (MATCH_DROP). This logic is needed to
            // consistently process / ignore packets no matter the current state of the APF program.
            // Note that userspace has no control (or knowledge) over when the APF program is
            // running.
            for (PacketSection section : mPacketSections) {
                if (section.type != PacketSection.Type.LIFETIME) continue;

                // the lifetime of the new RA.
                long lft = 0;
                switch (section.length) {
                    // section.length is guaranteed to be 2 or 4.
                    case 2: lft = getUint16(newRa.mPacket, section.start); break;
                    case 4: lft = getUint32(newRa.mPacket, section.start); break;
                }

                // WARNING: keep this in sync with Ra#generateFilter()!
                if (section.lifetime == 0) {
                    // Case 1) old lft == 0
                    if (section.min > 0) {
                        // a) in the presence of a min value.
                        // if lft >= min -> PASS
                        // gen.addJumpIfR0GreaterThan(section.min - 1, nextFilterLabel);
                        if (lft >= section.min) return MatchType.MATCH_PASS;
                    } else {
                        // b) if min is 0 / there is no min value.
                        // if lft > 0 -> PASS
                        // gen.addJumpIfR0GreaterThan(0, nextFilterLabel);
                        if (lft > 0) return MatchType.MATCH_PASS;
                    }
                } else if (section.min == 0) {
                    // Case 2b) section is not affected by any minimum.
                    //
                    // if lft < (oldLft + 2) // 3 -> PASS
                    // if lft > oldLft            -> PASS
                    // gen.addJumpIfR0LessThan(((section.lifetime + 2) / 3),
                    //        nextFilterLabel);
                    if (lft < (section.lifetime + 2) / 3) return MatchType.MATCH_PASS;
                    // gen.addJumpIfR0GreaterThan(section.lifetime, nextFilterLabel);
                    if (lft > section.lifetime) return MatchType.MATCH_PASS;
                } else if (section.lifetime < section.min) {
                    // Case 2a) 0 < old lft < min
                    //
                    // if lft == 0   -> PASS
                    // if lft >= min -> PASS
                    // gen.addJumpIfR0Equals(0, nextFilterLabel);
                    if (lft == 0) return MatchType.MATCH_PASS;
                    // gen.addJumpIfR0GreaterThan(section.min - 1, nextFilterLabel);
                    if (lft >= section.min) return MatchType.MATCH_PASS;
                } else if (section.lifetime <= 3 * (long) section.min) {
                    // Case 3a) min <= old lft <= 3 * min
                    // Note that:
                    // "(old lft + 2) / 3 <= min" is equivalent to "old lft <= 3 * min"
                    //
                    // Essentially, in this range there is no "renumbering support", as the
                    // renumbering constant of 1/3 * old lft is smaller than the minimum
                    // lifetime accepted by the kernel / userspace.
                    //
                    // if lft == 0     -> PASS
                    // if lft > oldLft -> PASS
                    // gen.addJumpIfR0Equals(0, nextFilterLabel);
                    if (lft == 0) return MatchType.MATCH_PASS;
                    // gen.addJumpIfR0GreaterThan(section.lifetime, nextFilterLabel);
                    if (lft > section.lifetime) return MatchType.MATCH_PASS;
                } else {
                    // Case 4a) otherwise
                    //
                    // if lft == 0                  -> PASS
                    // if lft < min                 -> CONTINUE
                    // if lft < (oldLft + 2) // 3   -> PASS
                    // if lft > oldLft              -> PASS
                    // gen.addJumpIfR0Equals(0, nextFilterLabel);
                    if (lft == 0) return MatchType.MATCH_PASS;
                    // gen.addJumpIfR0LessThan(section.min, continueLabel);
                    if (lft < section.min) continue;
                    // gen.addJumpIfR0LessThan(((section.lifetime + 2) / 3),
                    //         nextFilterLabel);
                    if (lft < (section.lifetime + 2) / 3) return MatchType.MATCH_PASS;
                    // gen.addJumpIfR0GreaterThan(section.lifetime, nextFilterLabel);
                    if (lft > section.lifetime) return MatchType.MATCH_PASS;
                }
            }

            return MatchType.MATCH_DROP;
        }

        // Get the number of seconds in which some of the information contained in this RA expires.
        private int getExpirationTime() {
            // While technically most lifetimes in the RA are u32s, as far as the RA filter is
            // concerned, INT_MAX is still a *much* longer lifetime than any filter would ever
            // reasonably be active for.
            // Clamp expirationTime at INT_MAX.
            int expirationTime = Integer.MAX_VALUE;
            for (PacketSection section : mPacketSections) {
                if (section.type != PacketSection.Type.LIFETIME) {
                    continue;
                }
                // Ignore lifetimes below section.min and always ignore 0 lifetimes.
                if (section.lifetime < Math.max(section.min, 1)) {
                    continue;
                }

                expirationTime = (int) Math.min(expirationTime, section.lifetime);
            }
            return expirationTime;
        }

        // Filter for a fraction of the expiration time and adjust for the age of the RA.
        int getRemainingFilterLft(int currentTimeSeconds) {
            int filterLifetime = ((mExpirationTime / FRACTION_OF_LIFETIME_TO_FILTER)
                    - (currentTimeSeconds - mLastSeen));
            filterLifetime = Math.max(0, filterLifetime);
            // Clamp filterLifetime to <= 65535, so it fits in 2 bytes.
            return Math.min(65535, filterLifetime);
        }

        // Append a filter for this RA to {@code gen}. Jump to DROP_LABEL if it should be dropped.
        // Jump to the next filter if packet doesn't match this RA.
        void generateFilter(ApfV4GeneratorBase<?> gen, int timeSeconds)
                throws IllegalInstructionException {
            short nextFilterLabel = gen.getUniqueLabel();
            // Skip if packet is not the right size
            gen.addLoadFromMemory(R0, MemorySlot.PACKET_SIZE);
            gen.addJumpIfR0NotEquals(mPacket.capacity(), nextFilterLabel);
            // Skip filter if expired
            gen.addLoadFromMemory(R0, MemorySlot.FILTER_AGE_SECONDS);
            gen.addJumpIfR0GreaterThan(getRemainingFilterLft(timeSeconds), nextFilterLabel);
            for (PacketSection section : mPacketSections) {
                // Generate code to match the packet bytes.
                if (section.type == PacketSection.Type.MATCH) {
                    gen.addLoadImmediate(R0, section.start);
                    gen.addJumpIfBytesAtR0NotEqual(
                            Arrays.copyOfRange(mPacket.array(), section.start,
                                    section.start + section.length),
                            nextFilterLabel);
                } else {
                    switch (section.length) {
                        // length asserted to be either 2 or 4 on PacketSection construction
                        case 2: gen.addLoad16intoR0(section.start); break;
                        case 4: gen.addLoad32intoR0(section.start); break;
                    }

                    // WARNING: keep this in sync with matches()!
                    // For more information on lifetime comparisons in the APF bytecode, see
                    // go/apf-ra-filter.
                    if (section.lifetime == 0) {
                        // Case 1) old lft == 0
                        if (section.min > 0) {
                            // a) in the presence of a min value.
                            // if lft >= min -> PASS
                            gen.addJumpIfR0GreaterThan(section.min - 1, nextFilterLabel);
                        } else {
                            // b) if min is 0 / there is no min value.
                            // if lft > 0 -> PASS
                            gen.addJumpIfR0GreaterThan(0, nextFilterLabel);
                        }
                    } else if (section.min == 0) {
                        // Case 2b) section is not affected by any minimum.
                        //
                        // if lft < (oldLft + 2) // 3 -> PASS
                        // if lft > oldLft            -> PASS
                        gen.addJumpIfR0LessThan(((section.lifetime + 2) / 3),
                                nextFilterLabel);
                        gen.addJumpIfR0GreaterThan(section.lifetime, nextFilterLabel);
                    } else if (section.lifetime < section.min) {
                        // Case 2a) 0 < old lft < min
                        //
                        // if lft == 0   -> PASS
                        // if lft >= min -> PASS
                        gen.addJumpIfR0Equals(0, nextFilterLabel);
                        gen.addJumpIfR0GreaterThan(section.min - 1, nextFilterLabel);
                    } else if (section.lifetime <= 3 * (long) section.min) {
                        // Case 3a) min <= old lft <= 3 * min
                        // Note that:
                        // "(old lft + 2) / 3 <= min" is equivalent to "old lft <= 3 * min"
                        //
                        // Essentially, in this range there is no "renumbering support", as the
                        // renumbering constant of 1/3 * old lft is smaller than the minimum
                        // lifetime accepted by the kernel / userspace.
                        //
                        // if lft == 0     -> PASS
                        // if lft > oldLft -> PASS
                        gen.addJumpIfR0Equals(0, nextFilterLabel);
                        gen.addJumpIfR0GreaterThan(section.lifetime, nextFilterLabel);
                    } else {
                        final short continueLabel = gen.getUniqueLabel();
                        // Case 4a) otherwise
                        //
                        // if lft == 0                  -> PASS
                        // if lft < min                 -> CONTINUE
                        // if lft < (oldLft + 2) // 3   -> PASS
                        // if lft > oldLft              -> PASS
                        gen.addJumpIfR0Equals(0, nextFilterLabel);
                        gen.addJumpIfR0LessThan(section.min, continueLabel);
                        gen.addJumpIfR0LessThan(((section.lifetime + 2) / 3),
                                nextFilterLabel);
                        gen.addJumpIfR0GreaterThan(section.lifetime, nextFilterLabel);

                        // CONTINUE
                        gen.defineLabel(continueLabel);
                    }
                }
            }
            gen.addCountAndDrop(DROPPED_RA);
            gen.defineLabel(nextFilterLabel);
        }
    }

    // TODO: Refactor these subclasses to avoid so much repetition.
    private abstract static class KeepalivePacket {
        // Note that the offset starts from IP header.
        // These must be added ether header length when generating program.
        static final int IP_HEADER_OFFSET = 0;
        static final int IPV4_SRC_ADDR_OFFSET = IP_HEADER_OFFSET + 12;

        // Append a filter for this keepalive ack to {@code gen}.
        // Jump to drop if it matches the keepalive ack.
        // Jump to the next filter if packet doesn't match the keepalive ack.
        abstract void generateFilter(ApfV4GeneratorBase<?> gen)
                throws IllegalInstructionException;
    }

    // A class to hold NAT-T keepalive ack information.
    private class NattKeepaliveResponse extends KeepalivePacket {
        static final int UDP_HEADER_LEN = 8;

        protected class NattKeepaliveResponseData {
            public final byte[] srcAddress;
            public final int srcPort;
            public final byte[] dstAddress;
            public final int dstPort;

            NattKeepaliveResponseData(final NattKeepalivePacketDataParcelable sentKeepalivePacket) {
                srcAddress = sentKeepalivePacket.dstAddress;
                srcPort = sentKeepalivePacket.dstPort;
                dstAddress = sentKeepalivePacket.srcAddress;
                dstPort = sentKeepalivePacket.srcPort;
            }
        }

        protected final NattKeepaliveResponseData mPacket;
        protected final byte[] mSrcDstAddr;
        protected final byte[] mPortFingerprint;
        // NAT-T keepalive packet
        protected final byte[] mPayload = {(byte) 0xff};

        NattKeepaliveResponse(final NattKeepalivePacketDataParcelable sentKeepalivePacket) {
            mPacket = new NattKeepaliveResponseData(sentKeepalivePacket);
            mSrcDstAddr = CollectionUtils.concatArrays(mPacket.srcAddress, mPacket.dstAddress);
            mPortFingerprint = generatePortFingerprint(mPacket.srcPort, mPacket.dstPort);
        }

        byte[] generatePortFingerprint(int srcPort, int dstPort) {
            final ByteBuffer fp = ByteBuffer.allocate(4);
            fp.order(ByteOrder.BIG_ENDIAN);
            fp.putShort((short) srcPort);
            fp.putShort((short) dstPort);
            return fp.array();
        }

        @Override
        void generateFilter(ApfV4GeneratorBase<?> gen) throws IllegalInstructionException {
            final short nextFilterLabel = gen.getUniqueLabel();

            gen.addLoadImmediate(R0, ETH_HEADER_LEN + IPV4_SRC_ADDR_OFFSET);
            gen.addJumpIfBytesAtR0NotEqual(mSrcDstAddr, nextFilterLabel);

            // A NAT-T keepalive packet contains 1 byte payload with the value 0xff
            // Check payload length is 1
            gen.addLoadFromMemory(R0, MemorySlot.IPV4_HEADER_SIZE);
            gen.addAdd(UDP_HEADER_LEN);
            gen.addSwap();
            gen.addLoad16intoR0(IPV4_TOTAL_LENGTH_OFFSET);
            gen.addNeg(R1);
            gen.addAddR1ToR0();
            gen.addJumpIfR0NotEquals(1, nextFilterLabel);

            // Check that the ports match
            gen.addLoadFromMemory(R0, MemorySlot.IPV4_HEADER_SIZE);
            gen.addAdd(ETH_HEADER_LEN);
            gen.addJumpIfBytesAtR0NotEqual(mPortFingerprint, nextFilterLabel);

            // Payload offset = R0 + UDP header length
            gen.addAdd(UDP_HEADER_LEN);
            gen.addJumpIfBytesAtR0NotEqual(mPayload, nextFilterLabel);

            gen.addCountAndDrop(DROPPED_IPV4_NATT_KEEPALIVE);
            gen.defineLabel(nextFilterLabel);
        }

        public String toString() {
            try {
                return String.format("%s -> %s",
                        ConnectivityUtils.addressAndPortToString(
                                InetAddress.getByAddress(mPacket.srcAddress), mPacket.srcPort),
                        ConnectivityUtils.addressAndPortToString(
                                InetAddress.getByAddress(mPacket.dstAddress), mPacket.dstPort));
            } catch (UnknownHostException e) {
                return "Unknown host";
            }
        }
    }

    // A class to hold TCP keepalive ack information.
    private abstract static class TcpKeepaliveAck extends KeepalivePacket {
        protected static class TcpKeepaliveAckData {
            public final byte[] srcAddress;
            public final int srcPort;
            public final byte[] dstAddress;
            public final int dstPort;
            public final int seq;
            public final int ack;

            // Create the characteristics of the ack packet from the sent keepalive packet.
            TcpKeepaliveAckData(final TcpKeepalivePacketDataParcelable sentKeepalivePacket) {
                srcAddress = sentKeepalivePacket.dstAddress;
                srcPort = sentKeepalivePacket.dstPort;
                dstAddress = sentKeepalivePacket.srcAddress;
                dstPort = sentKeepalivePacket.srcPort;
                seq = sentKeepalivePacket.ack;
                ack = sentKeepalivePacket.seq + 1;
            }
        }

        protected final TcpKeepaliveAckData mPacket;
        protected final byte[] mSrcDstAddr;
        protected final byte[] mPortSeqAckFingerprint;

        TcpKeepaliveAck(final TcpKeepaliveAckData packet, final byte[] srcDstAddr) {
            mPacket = packet;
            mSrcDstAddr = srcDstAddr;
            mPortSeqAckFingerprint = generatePortSeqAckFingerprint(mPacket.srcPort,
                    mPacket.dstPort, mPacket.seq, mPacket.ack);
        }

        static byte[] generatePortSeqAckFingerprint(int srcPort, int dstPort, int seq, int ack) {
            final ByteBuffer fp = ByteBuffer.allocate(12);
            fp.order(ByteOrder.BIG_ENDIAN);
            fp.putShort((short) srcPort);
            fp.putShort((short) dstPort);
            fp.putInt(seq);
            fp.putInt(ack);
            return fp.array();
        }

        public String toString() {
            try {
                return String.format("%s -> %s , seq=%d, ack=%d",
                        ConnectivityUtils.addressAndPortToString(
                                InetAddress.getByAddress(mPacket.srcAddress), mPacket.srcPort),
                        ConnectivityUtils.addressAndPortToString(
                                InetAddress.getByAddress(mPacket.dstAddress), mPacket.dstPort),
                        Integer.toUnsignedLong(mPacket.seq),
                        Integer.toUnsignedLong(mPacket.ack));
            } catch (UnknownHostException e) {
                return "Unknown host";
            }
        }

        // Append a filter for this keepalive ack to {@code gen}.
        // Jump to drop if it matches the keepalive ack.
        // Jump to the next filter if packet doesn't match the keepalive ack.
        abstract void generateFilter(ApfV4GeneratorBase<?> gen)
                throws IllegalInstructionException;
    }

    private class TcpKeepaliveAckV4 extends TcpKeepaliveAck {

        TcpKeepaliveAckV4(final TcpKeepalivePacketDataParcelable sentKeepalivePacket) {
            this(new TcpKeepaliveAckData(sentKeepalivePacket));
        }
        TcpKeepaliveAckV4(final TcpKeepaliveAckData packet) {
            super(packet, CollectionUtils.concatArrays(packet.srcAddress,
                    packet.dstAddress) /* srcDstAddr */);
        }

        @Override
        void generateFilter(ApfV4GeneratorBase<?> gen) throws IllegalInstructionException {
            final short nextFilterLabel = gen.getUniqueLabel();

            gen.addLoadImmediate(R0, ETH_HEADER_LEN + IPV4_SRC_ADDR_OFFSET);
            gen.addJumpIfBytesAtR0NotEqual(mSrcDstAddr, nextFilterLabel);

            // Skip to the next filter if it's not zero-sized :
            // TCP_HEADER_SIZE + IPV4_HEADER_SIZE - ipv4_total_length == 0
            // Load the IP header size into R1
            gen.addLoadFromMemory(R1, MemorySlot.IPV4_HEADER_SIZE);
            // Load the TCP header size into R0 (it's indexed by R1)
            gen.addLoad8R1IndexedIntoR0(ETH_HEADER_LEN + TCP_HEADER_SIZE_OFFSET);
            // Size offset is in the top nibble, bottom nibble is reserved,
            // but not necessarily zero.  Thus we need to >> 4 then << 2,
            // achieve this by >> 2 and masking with 0b00111100.
            gen.addRightShift(2);
            gen.addAnd(0x3C);
            // R0 += R1 -> R0 contains TCP + IP headers length
            gen.addAddR1ToR0();
            // Load IPv4 total length
            gen.addSwap();
            gen.addLoad16intoR0(IPV4_TOTAL_LENGTH_OFFSET);
            gen.addNeg(R1);
            gen.addAddR1ToR0();
            gen.addJumpIfR0NotEquals(0, nextFilterLabel);
            // Add IPv4 header length
            gen.addLoadFromMemory(R1, MemorySlot.IPV4_HEADER_SIZE);
            gen.addLoadImmediate(R0, ETH_HEADER_LEN);
            gen.addAddR1ToR0();
            gen.addJumpIfBytesAtR0NotEqual(mPortSeqAckFingerprint, nextFilterLabel);

            gen.addCountAndDrop(DROPPED_IPV4_KEEPALIVE_ACK);
            gen.defineLabel(nextFilterLabel);
        }
    }

    private static class TcpKeepaliveAckV6 extends TcpKeepaliveAck {
        TcpKeepaliveAckV6(final TcpKeepalivePacketDataParcelable sentKeepalivePacket) {
            this(new TcpKeepaliveAckData(sentKeepalivePacket));
        }
        TcpKeepaliveAckV6(final TcpKeepaliveAckData packet) {
            super(packet, CollectionUtils.concatArrays(packet.srcAddress,
                    packet.dstAddress) /* srcDstAddr */);
        }

        @Override
        void generateFilter(ApfV4GeneratorBase<?> gen) {
            throw new UnsupportedOperationException("IPv6 TCP Keepalive is not supported yet");
        }
    }

    // Maximum number of RAs to filter for.
    private static final int MAX_RAS = 10;

    private final ArrayList<Ra> mRas = new ArrayList<>();
    private int mNumFilteredRas = 0;
    private final SparseArray<KeepalivePacket> mKeepalivePackets = new SparseArray<>();

    // We don't want to filter an RA for it's whole lifetime as it'll be expired by the time we ever
    // see a refresh.  Using half the lifetime might be a good idea except for the fact that
    // packets may be dropped, so let's use 6.
    private static final int FRACTION_OF_LIFETIME_TO_FILTER = 6;

    // When did we last install a filter program? In seconds since Unix Epoch.
    private int mLastTimeInstalledProgram;
    // How long should the last installed filter program live for? In seconds.
    private int mLastInstalledProgramMinLifetime;

    // For debugging only. The last program installed.
    private byte[] mLastInstalledProgram;

    /**
     * For debugging only. Contains the latest APF buffer snapshot captured from the firmware.
     * <p>
     * A typical size for this buffer is 4KB. It is present only if the WiFi HAL supports
     * IWifiStaIface#readApfPacketFilterData(), and the APF interpreter advertised support for
     * the opcodes to access the data buffer (LDDW and STDW).
     */
    @Nullable
    private byte[] mDataSnapshot;

    // How many times the program was updated since we started.
    private int mNumProgramUpdates = 0;
    // The maximum program size that updated since we started.
    private int mMaxProgramSize = 0;
    // The maximum number of distinct RAs
    private int mMaxDistinctRas = 0;

    /**
     * Generate filter code to process ARP packets. Execution of this code ends in either the
     * DROP_LABEL or PASS_LABEL and does not fall off the end.
     * Preconditions:
     *  - Packet being filtered is ARP
     */
    private void generateArpFilter(ApfV4GeneratorBase<?> gen)
            throws IllegalInstructionException {
        // Here's a basic summary of what the ARP filter program does:
        //
        // if clat is enabled (and we're thus IPv6-only)
        //   drop
        // if not ARP IPv4
        //   drop
        // if unknown ARP opcode (ie. not reply or request)
        //   drop
        //
        // if ARP reply:
        //   if source ip is 0.0.0.0
        //     drop
        //   if unicast (or multicast)
        //     pass
        //   if interface has no IPv4 address
        //     if target ip is 0.0.0.0
        //       drop
        //   else
        //     if target ip is not the interface ip
        //       drop
        //   pass
        //
        // if ARP request:
        //   if interface has IPv4 address
        //     if target ip is not the interface ip
        //       drop
        //   pass

        // For IPv6 only network, drop all ARP packet.
        if (mHasClat) {
            gen.addCountAndDrop(DROPPED_ARP_V6_ONLY);
            return;
        }

        // Drop if not ARP IPv4.
        gen.addLoadImmediate(R0, ARP_HEADER_OFFSET);
        gen.addCountAndDropIfBytesAtR0NotEqual(ARP_IPV4_HEADER, DROPPED_ARP_NON_IPV4);

        final short checkArpRequest = gen.getUniqueLabel();

        gen.addLoad16intoR0(ARP_OPCODE_OFFSET);
        gen.addJumpIfR0Equals(ARP_OPCODE_REQUEST, checkArpRequest); // Skip to arp request check.
        // Drop if unknown ARP opcode.
        gen.addCountAndDropIfR0NotEquals(ARP_OPCODE_REPLY, DROPPED_ARP_UNKNOWN);

        /*----------  Handle ARP Replies. ----------*/

        // Drop if ARP reply source IP is 0.0.0.0
        gen.addLoad32intoR0(ARP_SOURCE_IP_ADDRESS_OFFSET);
        gen.addCountAndDropIfR0Equals(IPV4_ANY_HOST_ADDRESS, DROPPED_ARP_REPLY_SPA_NO_HOST);

        // Pass if non-broadcast reply.
        // This also accepts multicast arp, but we assume those don't exist.
        gen.addLoadImmediate(R0, ETH_DEST_ADDR_OFFSET);
        gen.addCountAndPassIfBytesAtR0NotEqual(ETHER_BROADCAST, PASSED_ARP_UNICAST_REPLY);

        // It is a broadcast reply.
        if (mIPv4Address == null) {
            // When there is no IPv4 address, drop GARP replies (b/29404209).
            gen.addLoad32intoR0(ARP_TARGET_IP_ADDRESS_OFFSET);
            gen.addCountAndDropIfR0Equals(IPV4_ANY_HOST_ADDRESS, DROPPED_GARP_REPLY);
        } else {
            // When there is an IPv4 address, drop broadcast replies with a different target IPv4
            // address.
            gen.addLoad32intoR0(ARP_TARGET_IP_ADDRESS_OFFSET);
            gen.addCountAndDropIfR0NotEquals(bytesToBEInt(mIPv4Address), DROPPED_ARP_OTHER_HOST);
        }
        gen.addCountAndPass(PASSED_ARP_BROADCAST_REPLY);

        /*----------  Handle ARP Requests. ----------*/

        gen.defineLabel(checkArpRequest);
        if (mIPv4Address != null) {
            // When there is an IPv4 address, drop unicast/broadcast requests with a different
            // target IPv4 address.
            gen.addLoad32intoR0(ARP_TARGET_IP_ADDRESS_OFFSET);
            gen.addCountAndDropIfR0NotEquals(bytesToBEInt(mIPv4Address), DROPPED_ARP_OTHER_HOST);

            if (enableArpOffload()) {
                ApfV6GeneratorBase<?> v6Gen = (ApfV6GeneratorBase<?>) gen;
                // Ethernet requires that all packets be at least 60 bytes long
                v6Gen.addAllocate(60)
                        .addPacketCopy(ETHER_SRC_ADDR_OFFSET, ETHER_ADDR_LEN)
                        .addDataCopy(mHardwareAddress)
                        .addDataCopy(FIXED_ARP_REPLY_HEADER)
                        .addDataCopy(mHardwareAddress)
                        .addWrite32(mIPv4Address)
                        .addPacketCopy(ETHER_SRC_ADDR_OFFSET, ETHER_ADDR_LEN)
                        .addPacketCopy(ARP_SOURCE_IP_ADDRESS_OFFSET, IPV4_ADDR_LEN)
                        .addLoadFromMemory(R0, MemorySlot.TX_BUFFER_OUTPUT_POINTER)
                        .addAdd(18)
                        .addStoreToMemory(MemorySlot.TX_BUFFER_OUTPUT_POINTER, R0)
                        .addTransmitWithoutChecksum()
                        .addCountAndDrop(DROPPED_ARP_REQUEST_REPLIED);
            }
        }
        // If we're not clat, and we don't have an ipv4 address, allow all ARP request to avoid
        // racing against DHCP.
        gen.addCountAndPass(PASSED_ARP_REQUEST);
    }

    /**
     * Generate filter code to reply and drop unicast ICMPv4 echo request.
     * <p>
     * On entry, we know it is IPv4 ethertype, but don't know anything else.
     * R0/R1 have nothing useful in them, and can be clobbered.
     */
    private void generateUnicastIpv4PingOffload(ApfV6GeneratorBase<?> gen)
            throws IllegalInstructionException {

        final short skipIpv4PingFilter = gen.getUniqueLabel();
        // Check 1) it's not a fragment. 2) it's ICMP.
        // If condition not match then skip the ping filter logic
        gen.addJumpIfNotUnfragmentedIPv4Protocol(IPPROTO_ICMP, skipIpv4PingFilter);

        // Only offload unicast Ipv4 ping request for now.
        // While we could potentially support offloading multicast and broadcast ping requests in
        // the future, such packets will likely be dropped by multicast filters.
        // Since the device may have packet forwarding enabled, APF needs to pass any received
        // unicast IPv4 ping not destined for the device's IP address to the kernel.
        gen.addLoadImmediate(R0, ETHER_DST_ADDR_OFFSET)
                .addJumpIfBytesAtR0NotEqual(mHardwareAddress, skipIpv4PingFilter)
                .addLoadImmediate(R0, IPV4_DEST_ADDR_OFFSET)
                .addJumpIfBytesAtR0NotEqual(mIPv4Address, skipIpv4PingFilter);

        // Ignore ping packets with IPv4 options (header size != 20) as they are rare.
        // Pass them to the kernel to save bytecode space.
        gen.addLoadFromMemory(R0, MemorySlot.IPV4_HEADER_SIZE)
                .addJumpIfR0NotEquals(IPV4_HEADER_MIN_LEN, skipIpv4PingFilter);

        // We need to check if the packet is sufficiently large to be a valid ICMP packet.
        gen.addLoadFromMemory(R0, MemorySlot.PACKET_SIZE)
                .addCountAndDropIfR0LessThan(
                        ETHER_HEADER_LEN + IPV4_HEADER_MIN_LEN + ICMP_HEADER_LEN,
                        DROPPED_IPV4_ICMP_INVALID);

        // If it is not a ICMP echo request, then skip.
        gen.addLoad8intoR0(ICMP4_TYPE_NO_OPTIONS_OFFSET)
                .addJumpIfR0NotEquals(ICMP_ECHO, skipIpv4PingFilter);

        final int defaultTtl = mDependencies.getIpv4DefaultTtl();
        // Construct the ICMP echo reply packet.
        gen.addLoadFromMemory(R0, MemorySlot.PACKET_SIZE)
                .addAllocateR0()
                .addPacketCopy(ETHER_SRC_ADDR_OFFSET, ETHER_ADDR_LEN) // Dst MAC address
                .addDataCopy(mHardwareAddress) // Src MAC address
                // Reuse the following fields from the input packet:
                // 2 bytes: EtherType
                // 4 bytes: version, IHL, TOS, total length
                // 4 bytes: identification, flags, fragment offset
                .addPacketCopy(ETH_ETHERTYPE_OFFSET, 10)
                // Ttl: default ttl, Protocol: IPPROTO_ICMP, checksum: 0
                .addWrite32((defaultTtl << 24) | (IPPROTO_ICMP << 16))
                .addWrite32(mIPv4Address) // Src ip
                .addPacketCopy(IPV4_SRC_ADDR_OFFSET, IPV4_ADDR_LEN) // Dst ip
                .addWrite32((ICMP_ECHOREPLY << 24)) // Type: echo reply, code: 0, checksum: 0
                // Copy identifier, sequence number and ping payload
                .addSub(ICMP4_CONTENT_NO_OPTIONS_OFFSET)
                .addLoadImmediate(R1, ICMP4_CONTENT_NO_OPTIONS_OFFSET)
                .addSwap() // Swaps R0 and R1, so they're the offset and length.
                .addPacketCopyFromR0LenR1()
                .addTransmitL4(
                        ETHER_HEADER_LEN, // ip_ofs
                        ICMP4_CHECKSUM_NO_OPTIONS_OFFSET, // csum_ofs
                        ICMP4_TYPE_NO_OPTIONS_OFFSET, // csum_start
                        0, // partial_sum
                        false // udp
                )
                .addCountAndDrop(DROPPED_IPV4_PING_REQUEST_REPLIED);

        gen.defineLabel(skipIpv4PingFilter);
    }

    /**
     * Generates filter code to handle IPv4 mDNS packets.
     * <p>
     * On entry, this filter knows it is processing an IPv4 packet. It will then process all IPv4
     * mDNS packets, either passing or dropping them. IPv4 non-mDNS packets are skipped.
     *
     * @param gen the APF generator to generate the filter code
     * @param labelCheckMdnsQueryPayload the label to jump to for checking the mDNS query payload
     */
    private void generateIPv4MdnsFilter(ApfV6GeneratorBase<?> gen,
            short labelCheckMdnsQueryPayload)
            throws IllegalInstructionException {
        final short skipMdnsFilter = gen.getUniqueLabel();

        // If the packet is too short to be a valid IPv4 mDNS packet, the filter is skipped.
        // For APF performance reasons, we check udp destination port before confirming it is
        // non-fragmented IPv4 udp packet. We proceed only if the destination port is 5353 (mDNS).
        // Otherwise, skip filtering.
        gen.addLoadFromMemory(R0, MemorySlot.PACKET_SIZE)
                .addJumpIfR0LessThan(
                        ETH_HEADER_LEN + IPV4_HEADER_MIN_LEN + UDP_HEADER_LEN + DNS_HEADER_LEN,
                        skipMdnsFilter)
                .addLoad16intoR0(IPV4_UDP_DESTINATION_PORT_NO_OPTIONS_OFFSET)
                .addJumpIfR0NotEquals(MDNS_PORT, skipMdnsFilter);

        // If the destination MAC address is not 01:00:5e:00:00:fb (the mDNS multicast MAC
        // address for IPv4 mDNS packet) or the device's MAC address, skip filtering.
        // We need to check both the mDNS multicast MAC address and the device's MAC address
        // because multicast to unicast conversion might have occurred.
        gen.addLoadImmediate(R0, ETH_DEST_ADDR_OFFSET)
                .addJumpIfBytesAtR0EqualNoneOf(
                        List.of(mHardwareAddress, ETH_MULTICAST_MDNS_V4_MAC_ADDRESS),
                        skipMdnsFilter
                );

        // Ignore packets with IPv4 options (header size not equal to 20) as they are rare.
        gen.addLoadFromMemory(R0, MemorySlot.IPV4_HEADER_SIZE)
                .addJumpIfR0NotEquals(IPV4_HEADER_MIN_LEN, skipMdnsFilter);

        // Skip filtering if the packet is not a non-fragmented IPv4 UDP packet.
        gen.addJumpIfNotUnfragmentedIPv4Protocol(IPPROTO_UDP, skipMdnsFilter);

        // Skip filtering if the IPv4 destination address is not 224.0.0.251 (the mDNS multicast
        // address).
        // Some devices can use unicast queries for mDNS to improve performance and reliability.
        // These packets are not currently offloaded and will be passed by APF and handled
        // by NsdService.
        gen.addLoad32intoR0(IPV4_DEST_ADDR_OFFSET)
                .addJumpIfR0NotEquals(MDNS_IPV4_ADDR_IN_LONG, skipMdnsFilter);

        // We now know that the packet is an mDNS packet,
        // i.e., a non-fragmented IPv4 UDP packet destined for port 5353 with the expected
        // destination MAC and IP addresses.

        // If the packet contains questions, check the query payload. Otherwise, check the
        // reply payload.
        gen.addLoad16intoR0(IPV4_DNS_QDCOUNT_NO_OPTIONS_OFFSET)
                // Set the UDP payload offset in R1 before potentially jumping to the payload
                // check logic.
                .addLoadImmediate(R1, IPV4_UDP_PAYLOAD_NO_OPTIONS_OFFSET)
                .addJumpIfR0NotEquals(0, labelCheckMdnsQueryPayload);

        // TODO: check the reply payload.
        if (mMulticastFilter) {
            gen.addCountAndDrop(DROPPED_MDNS);
        } else {
            gen.addCountAndPass(PASSED_MDNS);
        }

        gen.defineLabel(skipMdnsFilter);
    }

    /**
     * Generate filter code to process IPv4 packets. Execution of this code ends in either the
     * DROP_LABEL or PASS_LABEL and does not fall off the end.
     * Preconditions:
     *  - Packet being filtered is IPv4
     *
     * @param gen the APF generator to generate the filter code
     * @param labelCheckMdnsQueryPayload the label to jump to for checking the mDNS query payload
     */
    private void generateIPv4Filter(ApfV4GeneratorBase<?> gen, short labelCheckMdnsQueryPayload)
            throws IllegalInstructionException {
        // Here's a basic summary of what the IPv4 filter program does:
        //
        // if the network is IPv6 only network:
        //   if the packet is fragmented:
        //     drop
        //   if the packet is a dhcp packet comes from server:
        //     pass
        //   else
        //     drop
        //
        // (APFv6+ specific logic)
        // if it's mDNS:
        //   if it's a query:
        //     if the query matches one of the offload rules:
        //       transmit mDNS reply and drop
        //     else if filtering multicast (i.e. multicast lock not held):
        //       drop
        //     else
        //       pass
        //   else:
        //     if filtering multicast (i.e. multicast lock not held):
        //       drop
        //     else
        //       pass
        //
        // (APFv6+ specific logic)
        // if it's IGMP:
        //   if payload length is invalid (less than 8 or equal to 9, 10, 11):
        //     drop
        //   if the packet is an IGMP report:
        //     drop
        //   if the packet is not an IGMP query:
        //     drop
        //   if the group_addr is not 0.0.0.0, then it is group specific query:
        //     pass
        //   ===== handle IGMPv1/v2/v3 general query =====
        //   if the IPv4 dst addr is not 224.0.0.1:
        //     drop
        //   if the packet length >= 12, then it is IGMPv3:
        //     transmit IGMPv3 report and drop
        //   else if the packet length == 8, then it is either IGMPv1 or IGMPv2:
        //     if the max_res_code == 0, then it is IGMPv1:
        //       pass
        //     else it is IGMPv2:
        //       transmit IGMPv2 reports (one report per group) and drop
        //
        // if filtering multicast (i.e. multicast lock not held):
        //   if it's DHCP destined to our MAC:
        //     pass
        //   if it's L2 broadcast:
        //     drop
        //   if it's IPv4 multicast:
        //     drop
        //   if it's IPv4 broadcast:
        //     drop
        //
        // if keepalive ack
        //   drop
        //
        // (APFv6+ specific logic) if it's unicast IPv4 ICMP echo request to our host:
        //    transmit echo reply and drop
        //
        // pass

        if (mHasClat) {
            // Check 1) it's not a fragment. 2) it's UDP.
            // Load 16 bit frag flags/offset field, 8 bit ttl, 8 bit protocol
            gen.addLoad32intoR0(IPV4_FRAGMENT_OFFSET_OFFSET);
            // Mask out the reserved and don't fragment bits, plus the TTL field.
            // Because:
            //   IPV4_FRAGMENT_OFFSET_MASK = 0x1fff
            //   IPV4_FRAGMENT_MORE_FRAGS_MASK = 0x2000
            // hence this constant ends up being 0x3FFF00FF.
            // We want the more flag bit and offset to be 0 (ie. not a fragment),
            // so after this masking we end up with just the ip protocol (hopefully UDP).
            gen.addAnd((IPV4_FRAGMENT_MORE_FRAGS_MASK | IPV4_FRAGMENT_OFFSET_MASK) << 16 | 0xFF);
            gen.addCountAndDropIfR0NotEquals(IPPROTO_UDP, DROPPED_IPV4_NON_DHCP4);
            // Check it's addressed to DHCP client port.
            gen.addLoadFromMemory(R1, MemorySlot.IPV4_HEADER_SIZE);
            gen.addLoad32R1IndexedIntoR0(TCP_UDP_SOURCE_PORT_OFFSET);
            gen.addCountAndDropIfR0NotEquals(DHCP_SERVER_PORT << 16 | DHCP_CLIENT_PORT,
                    DROPPED_IPV4_NON_DHCP4);
            gen.addCountAndPass(PASSED_IPV4_FROM_DHCPV4_SERVER);
            return;
        }

        if (enableMdns4Offload()) {
            generateIPv4MdnsFilter((ApfV6GeneratorBase<?>) gen, labelCheckMdnsQueryPayload);
        }

        if (enableIgmpOffload()) {
            generateIgmpFilter((ApfV6GeneratorBase<?>) gen);
        }

        if (mMulticastFilter) {
            final short skipDhcpv4Filter = gen.getUniqueLabel();

            // Pass DHCP addressed to us.
            // Check 1) it's not a fragment. 2) it's UDP.
            gen.addJumpIfNotUnfragmentedIPv4Protocol(IPPROTO_UDP, skipDhcpv4Filter);
            // Check it's addressed to DHCP client port.
            gen.addLoadFromMemory(R1, MemorySlot.IPV4_HEADER_SIZE);
            gen.addLoad16R1IndexedIntoR0(TCP_UDP_DESTINATION_PORT_OFFSET);
            gen.addJumpIfR0NotEquals(DHCP_CLIENT_PORT, skipDhcpv4Filter);
            // Check it's DHCP to our MAC address.
            gen.addLoadImmediate(R0, DHCP_CLIENT_MAC_OFFSET);
            // NOTE: Relies on R1 containing IPv4 header offset.
            gen.addAddR1ToR0();
            gen.addJumpIfBytesAtR0NotEqual(mHardwareAddress, skipDhcpv4Filter);
            gen.addCountAndPass(PASSED_DHCP);

            // Drop all multicasts/broadcasts.
            gen.defineLabel(skipDhcpv4Filter);

            // If IPv4 destination address is in multicast range, drop.
            gen.addLoad8intoR0(IPV4_DEST_ADDR_OFFSET);
            gen.addAnd(0xf0);
            gen.addCountAndDropIfR0Equals(0xe0, DROPPED_IPV4_MULTICAST);

            // If IPv4 broadcast packet, drop regardless of L2 (b/30231088).
            gen.addLoad32intoR0(IPV4_DEST_ADDR_OFFSET);
            gen.addCountAndDropIfR0Equals(IPV4_BROADCAST_ADDRESS, DROPPED_IPV4_BROADCAST_ADDR);
            if (mIPv4Address != null && mIPv4PrefixLength < 31) {
                int broadcastAddr = ipv4BroadcastAddress(mIPv4Address, mIPv4PrefixLength);
                gen.addCountAndDropIfR0Equals(broadcastAddr, DROPPED_IPV4_BROADCAST_NET);
            }
        }

        // If any TCP keepalive filter matches, drop
        generateV4KeepaliveFilters(gen);

        // If any NAT-T keepalive filter matches, drop
        generateV4NattKeepaliveFilters(gen);

        // If TCP unicast on port 7, drop
        generateV4TcpPort7Filter(gen);

        if (enableIpv4PingOffload()) {
            generateUnicastIpv4PingOffload((ApfV6GeneratorBase<?>) gen);
        }

        if (mMulticastFilter) {
            // Otherwise, this is an IPv4 unicast, pass
            // If L2 broadcast packet, drop.
            // TODO: can we invert this condition to fall through to the common pass case below?
            gen.addLoadImmediate(R0, ETH_DEST_ADDR_OFFSET);
            gen.addCountAndPassIfBytesAtR0NotEqual(ETHER_BROADCAST, PASSED_IPV4_UNICAST);
            gen.addCountAndDrop(DROPPED_IPV4_L2_BROADCAST);
        }

        // Otherwise, pass
        gen.addCountAndPass(PASSED_IPV4);
    }

    private void generateKeepaliveFilters(ApfV4GeneratorBase<?> gen, Class<?> filterType, int proto,
            int offset, short label) throws IllegalInstructionException {
        final boolean haveKeepaliveResponses = CollectionUtils.any(mKeepalivePackets,
                filterType::isInstance);

        // If no keepalive packets of this type
        if (!haveKeepaliveResponses) return;

        // If not the right proto, skip keepalive filters
        gen.addLoad8intoR0(offset);
        gen.addJumpIfR0NotEquals(proto, label);

        // Drop Keepalive responses
        for (int i = 0; i < mKeepalivePackets.size(); ++i) {
            final KeepalivePacket response = mKeepalivePackets.valueAt(i);
            if (filterType.isInstance(response)) response.generateFilter(gen);
        }

        gen.defineLabel(label);
    }

    private void generateV4KeepaliveFilters(ApfV4GeneratorBase<?> gen)
            throws IllegalInstructionException {
        generateKeepaliveFilters(gen, TcpKeepaliveAckV4.class, IPPROTO_TCP, IPV4_PROTOCOL_OFFSET,
                gen.getUniqueLabel());
    }

    private void generateV4NattKeepaliveFilters(ApfV4GeneratorBase<?> gen)
            throws IllegalInstructionException {
        generateKeepaliveFilters(gen, NattKeepaliveResponse.class,
                IPPROTO_UDP, IPV4_PROTOCOL_OFFSET, gen.getUniqueLabel());
    }

    private List<byte[]> getSolicitedNodeMcastAddressSuffix(
            @NonNull List<byte[]> ipv6Addresses) {
        final List<byte[]> suffixes = new ArrayList<>();
        for (byte[] addr: ipv6Addresses) {
            suffixes.add(Arrays.copyOfRange(addr, 13,  16));
        }
        return suffixes;
    }

    private List<byte[]> getIpv6Addresses(
            boolean includeNonTentative, boolean includeTentative, boolean includeAnycast) {
        final List<byte[]> addresses = new ArrayList<>();
        if (includeNonTentative) {
            for (Inet6Address addr : mIPv6NonTentativeAddresses) {
                addresses.add(addr.getAddress());
            }
        }

        if (includeTentative) {
            for (Inet6Address addr : mIPv6TentativeAddresses) {
                addresses.add(addr.getAddress());
            }
        }

        if (includeAnycast) {
            addresses.addAll(mDependencies.getAnycast6Addresses(mInterfaceParams.name));
        }
        return addresses;
    }

    private List<byte[]> getKnownMacAddresses() {
        final List<byte[]> addresses = new ArrayList<>();
        addresses.addAll(mDependencies.getEtherMulticastAddresses(mInterfaceParams.name));
        addresses.add(mHardwareAddress);
        addresses.add(ETHER_BROADCAST);
        return addresses;
    }

    /**
     * Generate allocate and transmit code to send ICMPv6 non-DAD NA packets.
     */
    private void generateNonDadNaTransmit(ApfV6GeneratorBase<?> gen)
            throws IllegalInstructionException {
        final int ipv6PayloadLen = ICMPV6_NA_HEADER_LEN + ICMPV6_ND_OPTION_TLLA_LEN;
        final int pktLen = ETH_HEADER_LEN + IPV6_HEADER_LEN + ipv6PayloadLen;

        gen.addAllocate(pktLen);

        // Ethernet Header
        gen.addPacketCopy(ICMP6_NS_OPTION_TYPE_OFFSET + 2, ETHER_ADDR_LEN)  // dst MAC address
                .addDataCopy(mHardwareAddress)  // src MAC address
                .addWriteU16(ETH_P_IPV6);  // IPv6 type

        int tclass = mDependencies.getNdTrafficClass(mInterfaceParams.name);
        int vtf = (0x60000000 | (tclass << 20));
        // IPv6 header
        gen.addWrite32(vtf)  // IPv6 Header: version, traffic class, flowlabel
                // payload length (2 bytes) | next header: ICMPv6 (1 byte) | hop limit (1 byte)
                .addWrite32((ipv6PayloadLen << 16) | ((IPPROTO_ICMPV6 << 8) | 255))
                // target ip is guaranteed to be non-tentative as we already check before
                // we call transmit, but the link local ip can potentially be tentative.
                .addPacketCopy(ICMP6_NS_TARGET_IP_OFFSET, IPV6_ADDR_LEN)  // src ip
                .addPacketCopy(IPV6_SRC_ADDR_OFFSET, IPV6_ADDR_LEN);  // dst ip

        // ICMPv6 header and payload
        // ICMPv6 type: NA (1 byte) | code: 0 (1 byte) | checksum: set to payload size (2 bytes)
        gen.addWrite32((ICMPV6_NEIGHBOR_ADVERTISEMENT << 24) | ipv6PayloadLen)
                // Always set Router flag to prevent host deleting routes point at the router
                // Always set Override flag to update neighbor's cache
                // Solicited flag set to 1 if non DAD, refer to RFC4861#7.2.4
                .addWrite32(0xe0000000) // flags: R=1, S=1, O=1
                .addPacketCopy(ICMP6_NS_TARGET_IP_OFFSET, IPV6_ADDR_LEN) // target address
                // lla option: type (1 byte) | lla option: length (1 byte)
                .addWriteU16((ICMPV6_ND_OPTION_TLLA << 8) | 1)
                .addDataCopy(mHardwareAddress);  // lla option: link layer address

        gen.addTransmitL4(
                ETHER_HEADER_LEN,   // ip_ofs
                ICMP6_CHECKSUM_OFFSET,  // csum_ofs
                IPV6_SRC_ADDR_OFFSET,   // csum_start
                IPPROTO_ICMPV6, // partial_sum
                false   // udp
        );
    }

    private void generateNsFilter(ApfV6GeneratorBase<?> v6Gen)
            throws IllegalInstructionException {
        final List<byte[]> allIPv6Addrs = getIpv6Addresses(
                true /* includeNonTentative */,
                true /* includeTentative */,
                true /* includeAnycast */);
        if (allIPv6Addrs.isEmpty()) {
            // If there is no IPv6 link local address, allow all NS packets to avoid racing
            // against RS.
            v6Gen.addCountAndPass(PASSED_IPV6_ICMP);
            return;
        }

        // Warning: APF program may temporarily filter NS packets targeted for anycast addresses
        // used by processes other than clatd. This is because APF cannot reliably detect signal
        // on when IPV6_{JOIN,LEAVE}_ANYCAST is triggered.
        final List<byte[]> allMACs = getKnownMacAddresses();
        v6Gen.addLoadImmediate(R0, ETH_DEST_ADDR_OFFSET)
                .addCountAndDropIfBytesAtR0EqualsNoneOf(allMACs, DROPPED_IPV6_NS_OTHER_HOST);

        // Dst IPv6 address check:
        final List<byte[]> allSuffixes = getSolicitedNodeMcastAddressSuffix(allIPv6Addrs);
        final short notIpV6SolicitedNodeMcast = v6Gen.getUniqueLabel();
        final short endOfIpV6DstCheck = v6Gen.getUniqueLabel();
        v6Gen.addLoadImmediate(R0, IPV6_DEST_ADDR_OFFSET)
                .addJumpIfBytesAtR0NotEqual(IPV6_SOLICITED_NODES_PREFIX, notIpV6SolicitedNodeMcast)
                .addAdd(13)
                .addCountAndDropIfBytesAtR0EqualsNoneOf(allSuffixes, DROPPED_IPV6_NS_OTHER_HOST)
                .addJump(endOfIpV6DstCheck)
                .defineLabel(notIpV6SolicitedNodeMcast)
                .addCountAndDropIfBytesAtR0EqualsNoneOf(allIPv6Addrs, DROPPED_IPV6_NS_OTHER_HOST)
                .defineLabel(endOfIpV6DstCheck);

        // Hop limit not 255, NS requires hop limit to be 255 -> drop
        v6Gen.addLoad8intoR0(IPV6_HOP_LIMIT_OFFSET)
                .addCountAndDropIfR0NotEquals(255, DROPPED_IPV6_NS_INVALID);

        // payload length < 24 (8 bytes ICMP6 header + 16 bytes target address) -> drop
        v6Gen.addLoad16intoR0(IPV6_PAYLOAD_LEN_OFFSET)
                .addCountAndDropIfR0LessThan(24, DROPPED_IPV6_NS_INVALID);

        // ICMPv6 code not 0 -> drop
        v6Gen.addLoad8intoR0(ICMP6_CODE_OFFSET)
                .addCountAndDropIfR0NotEquals(0, DROPPED_IPV6_NS_INVALID);

        // target address (ICMPv6 NS payload)
        //   1) is one of tentative addresses -> pass
        //   2) is none of {non-tentative, anycast} addresses -> drop
        final List<byte[]> tentativeIPv6Addrs = getIpv6Addresses(
                false, /* includeNonTentative */
                true, /* includeTentative */
                false /* includeAnycast */
        );
        v6Gen.addLoadImmediate(R0, ICMP6_NS_TARGET_IP_OFFSET);
        if (!tentativeIPv6Addrs.isEmpty()) {
            v6Gen.addCountAndPassIfBytesAtR0EqualsAnyOf(
                    tentativeIPv6Addrs, PASSED_IPV6_ICMP);
        }

        final List<byte[]> nonTentativeIpv6Addrs = getIpv6Addresses(
                true, /* includeNonTentative */
                false, /* includeTentative */
                true /* includeAnycast */
        );
        if (nonTentativeIpv6Addrs.isEmpty()) {
            v6Gen.addCountAndDrop(DROPPED_IPV6_NS_OTHER_HOST);
            return;
        }
        v6Gen.addCountAndDropIfBytesAtR0EqualsNoneOf(
                nonTentativeIpv6Addrs, DROPPED_IPV6_NS_OTHER_HOST);

        // if source ip is unspecified (::), it's DAD request -> pass
        v6Gen.addLoadImmediate(R0, IPV6_SRC_ADDR_OFFSET)
                .addCountAndPassIfBytesAtR0Equal(IPV6_UNSPECIFIED_ADDRESS, PASSED_IPV6_ICMP);

        // Only offload NUD/Address resolution packets that have SLLA as the their first option.
        // For option-less NUD packets or NUD/Address resolution packets where
        // the first option is not SLLA, pass them to the kernel for handling.
        // if payload len < 32 -> pass
        v6Gen.addLoad16intoR0(IPV6_PAYLOAD_LEN_OFFSET)
                .addCountAndPassIfR0LessThan(32, PASSED_IPV6_ICMP);

        // if the first option is not SLLA -> pass
        // 0                   1                   2                   3
        // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |     Type      |    Length     |Link-Layer Addr  |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        v6Gen.addLoad8intoR0(ICMP6_NS_OPTION_TYPE_OFFSET)
                .addCountAndPassIfR0NotEquals(ICMPV6_ND_OPTION_SLLA, PASSED_IPV6_ICMP);

        // Src IPv6 address check:
        // if multicast address (FF::/8) or loopback address (00::/8) -> drop
        v6Gen.addLoad8intoR0(IPV6_SRC_ADDR_OFFSET)
                .addCountAndDropIfR0IsOneOf(Set.of(0L, 0xffL), DROPPED_IPV6_NS_INVALID);

        // if multicast MAC in SLLA option -> drop
        v6Gen.addLoad8intoR0(ICMP6_NS_OPTION_TYPE_OFFSET + 2)
                .addCountAndDropIfR0AnyBitsSet(1, DROPPED_IPV6_NS_INVALID);
        generateNonDadNaTransmit(v6Gen);
        v6Gen.addCountAndDrop(DROPPED_IPV6_NS_REPLIED_NON_DAD);
    }

    /**
     * Generates filter code to handle IPv6 mDNS packets.
     * <p>
     * On entry, this filter knows it is processing an IPv6 packet. It will then process all IPv6
     * mDNS packets, either passing or dropping them. IPv6 non-mDNS packets are skipped.
     *
     * @param gen the APF generator to generate the filter code
     * @param labelCheckMdnsQueryPayload the label to jump to for checking the mDNS query payload
     */
    private void generateIPv6MdnsFilter(ApfV6GeneratorBase<?> gen,
            short labelCheckMdnsQueryPayload) throws IllegalInstructionException {
        final short skipMdnsFilter = gen.getUniqueLabel();

        // If the packet is too short to be a valid IPv6 mDNS packet, the filter is skipped.
        // For APF performance reasons, we check udp destination port before confirming it is IPv6
        // udp packet. We proceed only if the destination port is 5353 (mDNS). Otherwise, skip
        // filtering.
        gen.addLoadFromMemory(R0, MemorySlot.PACKET_SIZE)
                .addJumpIfR0LessThan(
                        ETH_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN + DNS_HEADER_LEN,
                        skipMdnsFilter)
                .addLoad16intoR0(IPV6_UDP_DESTINATION_PORT_OFFSET)
                .addJumpIfR0NotEquals(MDNS_PORT, skipMdnsFilter);

        // If the destination MAC address is not 33:33:00:00:00:fb (the mDNS multicast MAC
        // address for IPv6 mDNS packet) or the device's MAC address, skip filtering.
        // We need to check both the mDNS multicast MAC address and the device's MAC address
        // because multicast to unicast conversion might have occurred.
        gen.addLoadImmediate(R0, ETH_DEST_ADDR_OFFSET)
                .addJumpIfBytesAtR0EqualNoneOf(
                        List.of(mHardwareAddress, ETH_MULTICAST_MDNS_V6_MAC_ADDRESS),
                        skipMdnsFilter
                );

        // Skip filtering if the packet is not an IPv6 UDP packet.
        gen.addLoad8intoR0(IPV6_NEXT_HEADER_OFFSET)
                .addJumpIfR0NotEquals(IPPROTO_UDP, skipMdnsFilter);

        // Skip filtering if the IPv6 destination address is not ff02::fb (the mDNS multicast
        // IPv6 address).
        // Some devices can use unicast queries for mDNS to improve performance and reliability.
        // These packets are not currently offloaded and will be passed by APF and handled
        // by NsdService.
        gen.addLoadImmediate(R0, IPV6_DEST_ADDR_OFFSET)
                .addJumpIfBytesAtR0NotEqual(MDNS_IPV6_ADDR, skipMdnsFilter);

        // We now know that the packet is an mDNS packet,
        // i.e., an IPv6 UDP packet destined for port 5353 with the expected destination MAC and IP
        // addresses.

        // If the packet contains questions, check the query payload. Otherwise, check the
        // reply payload.
        gen.addLoad16intoR0(IPV6_DNS_QDCOUNT_OFFSET)
                // Set the UDP payload offset in R1 before potentially jumping to the payload
                // check logic.
                .addLoadImmediate(R1, IPv6_UDP_PAYLOAD_OFFSET)
                .addJumpIfR0NotEquals(0, labelCheckMdnsQueryPayload);

        // TODO: check the reply payload.
        if (mMulticastFilter) {
            gen.addCountAndDrop(DROPPED_MDNS);
        } else {
            gen.addCountAndPass(PASSED_MDNS);
        }

        gen.defineLabel(skipMdnsFilter);
    }

    /**
     * Generate filter code to reply and drop unicast ICMPv6 echo request.
     * <p>
     * On entry, we know it is ICMPv6 packet, but don't know anything else.
     * R0 contains the u8 ICMPv6 type.
     * R1 contains nothing useful in it, and can be clobbered.
     */
    private void generateUnicastIpv6PingOffload(ApfV6GeneratorBase<?> gen)
            throws IllegalInstructionException {

        final short skipPing6Offload = gen.getUniqueLabel();
        gen.addJumpIfR0NotEquals(ICMPV6_ECHO_REQUEST_TYPE, skipPing6Offload);

        // Only offload unicast ping6.
        // While we could potentially support offloading multicast and broadcast ping6 requests in
        // the future, such packets will likely be dropped by the multicast filter.
        // Since the device may have packet forwarding enabled, APF needs to pass any received
        // unicast ping6 not destined for the device's IP address to the kernel.
        final List<byte[]> nonTentativeIPv6Addrs = getIpv6Addresses(
                true /* includeNonTentative */,
                false /* includeTentative */,
                false /* includeAnycast */);
        gen.addLoadImmediate(R0, ETHER_DST_ADDR_OFFSET)
                .addJumpIfBytesAtR0NotEqual(mHardwareAddress, skipPing6Offload)
                .addLoadImmediate(R0, IPV6_DEST_ADDR_OFFSET)
                .addJumpIfBytesAtR0EqualNoneOf(nonTentativeIPv6Addrs, skipPing6Offload);

        // We need to check if the packet is sufficiently large to be a valid ICMPv6 echo packet.
        gen.addLoadFromMemory(R0, MemorySlot.PACKET_SIZE)
                .addCountAndDropIfR0LessThan(
                        ETHER_HEADER_LEN + IPV6_HEADER_LEN + ICMP6_ECHO_REQUEST_HEADER_LEN,
                        DROPPED_IPV6_ICMP6_ECHO_REQUEST_INVALID);

        int hopLimit = mDependencies.getIpv6DefaultHopLimit(mInterfaceParams.name);
        // Construct the ICMPv6 echo reply packet.
        gen.addLoadFromMemory(R0, MemorySlot.PACKET_SIZE)
                .addAllocateR0()
                // Eth header
                .addPacketCopy(ETHER_SRC_ADDR_OFFSET, ETHER_ADDR_LEN) // Dst MAC address
                .addDataCopy(mHardwareAddress) // Src MAC address
                // Reuse the following fields from input packet
                //  2 byte: ethertype
                //  4 bytes: version, traffic class, flowlabel
                //  2 bytes: payload length
                //  1 byte: next header
                .addPacketCopy(ETH_ETHERTYPE_OFFSET, 9)
                .addWriteU8(hopLimit)
                .addPacketCopy(IPV6_DEST_ADDR_OFFSET, IPV6_ADDR_LEN) // Src ip
                .addPacketCopy(IPV6_SRC_ADDR_OFFSET, IPV6_ADDR_LEN) // Dst ip
                .addWriteU16((ICMP6_ECHO_REPLY << 8) | 0) // Type: echo reply, code: 0
                // Checksum: initialized to the IPv6 payload length as a partial checksum. The final
                // checksum will be calculated by the interpreter.
                .addPacketCopy(IPV6_PAYLOAD_LEN_OFFSET, 2)
                // Copy identifier, sequence number and ping payload
                .addSub(ICMP6_CONTENT_OFFSET)
                .addLoadImmediate(R1, ICMP6_CONTENT_OFFSET)
                .addSwap() // Swaps R0 and R1, so they're the offset and length.
                .addPacketCopyFromR0LenR1()
                .addTransmitL4(
                        ETHER_HEADER_LEN, // ip_ofs
                        ICMP6_CHECKSUM_OFFSET, // csum_ofs
                        IPV6_SRC_ADDR_OFFSET, // csum_start
                        IPPROTO_ICMPV6, // partial_sum
                        false // udp
                )
                .addCountAndDrop(DROPPED_IPV6_ICMP6_ECHO_REQUEST_REPLIED);

        gen.defineLabel(skipPing6Offload);
    }

    /**
     * Generate filter code to process IPv6 packets. Execution of this code ends in either the
     * DROP_LABEL or PASS_LABEL, or falls off the end for ICMPv6 packets.
     * Preconditions:
     *  - Packet being filtered is IPv6
     *
     * @param gen the APF generator to generate the filter code
     * @param labelCheckMdnsQueryPayload the label to jump to for checking the mDNS query payload
     */
    private void generateIPv6Filter(ApfV4GeneratorBase<?> gen, short labelCheckMdnsQueryPayload)
            throws IllegalInstructionException {
        // Here's a basic summary of what the IPv6 filter program does:
        //
        // if there is a HOPOPTS option present (e.g. MLD query)
        //   (APFv6+ specific logic)
        //   if MLD offload is enabled:
        //     if it is an MLDv1 report/done or MLDv2 report:
        //       drop
        //     if the payload length is invalid (25, 26, 27):
        //       drop
        //     if the IPv6 src addr is not link-local address:
        //       drop
        //     if the IPv6 hop limit is not 1:
        //       drop
        //     if it is an multicast address specific query (the MLD multicast address is not "::"):
        //       pass
        //     if the IPv6 dst addr is not ff02::1:
        //       drop
        //     if it is an MLDv2 general query (payload length is not 24):
        //       transmit MLDv2 report and drop
        //     else it is an MLDv1 general query:
        //       transmit MLDv1 reports (one report per multicast group) and drop
        //   else
        //     pass (on APFv2+)
        //
        // (APFv6+ specific logic)
        // if it's mDNS:
        //   if it's a query:
        //     if the query matches one of the offload rules:
        //       transmit mDNS reply and drop
        //     else if filtering multicast (i.e. multicast lock not held):
        //       drop
        //     else
        //       pass
        //   else:
        //     if filtering multicast (i.e. multicast lock not held):
        //       drop
        //     else
        //       pass
        //
        // if we're dropping multicast
        //   if it's not ICMPv6 or it's ICMPv6 but we're in doze mode:
        //     if it's multicast:
        //       drop
        //     pass
        //
        // (APFv6+ specific logic)
        // if it's ICMPv6 NS:
        //   if there are no IPv6 addresses (including link local address) on the interface:
        //     pass
        //   if MAC dst is none of known {unicast, multicast, broadcast} MAC addresses
        //     drop
        //   if IPv6 dst prefix is "ff02::1:ff00:0/104" but is none of solicited-node multicast
        //   IPv6 addresses:
        //     drop
        //   else if IPv6 dst is none of interface unicast IPv6 addresses (incl. anycast):
        //     drop
        //   if hop limit is not 255 (NS requires hop limit to be 255):
        //     drop
        //   if payload len < 24 (8 bytes ICMP6 header + 16 bytes target address):
        //     drop
        //   if ICMPv6 code is not 0:
        //     drop
        //   if target IP is one of tentative IPv6 addresses:
        //     pass
        //   if target IP is none of non-tentative IPv6 addresses (incl. anycast):
        //     drop
        //   if IPv6 src is unspecified (::):
        //     pass
        //   if payload len < 32 (8 bytes ICMP6 header + 16 bytes target address + 8 bytes option):
        //     pass
        //   if IPv6 src is multicast address (FF::/8) or loopback address (00::/8):
        //     drop
        //   if multicast MAC in SLLA option:
        //     drop
        //   transmit NA and drop
        //
        // (APFv6+ specific logic) if it's unicast ICMPv6 echo request to our host:
        //    transmit echo reply and drop
        //
        // if it's ICMPv6 RS to any:
        //   drop
        //
        // if it's ICMPv6 NA to anything in ff02::/120
        //   drop
        //
        // if keepalive ack
        //   drop

        gen.addLoad8intoR0(IPV6_NEXT_HEADER_OFFSET);

        if (enableMldOffload()) {
            generateMldFilter((ApfV6GeneratorBase<?>) gen);
        } else {
            gen.addCountAndPassIfR0Equals(IPPROTO_HOPOPTS, PASSED_IPV6_HOPOPTS);
        }

        if (enableMdns6Offload()) {
            generateIPv6MdnsFilter((ApfV6GeneratorBase<?>) gen, labelCheckMdnsQueryPayload);
            gen.addLoad8intoR0(IPV6_NEXT_HEADER_OFFSET);
        }

        // Drop multicast if the multicast filter is enabled.
        if (mMulticastFilter) {
            final short skipIPv6MulticastFilterLabel = gen.getUniqueLabel();
            final short dropAllIPv6MulticastsLabel = gen.getUniqueLabel();

            // While in doze mode, drop ICMPv6 multicast pings, let the others pass.
            // While awake, let all ICMPv6 multicasts through.
            if (mInDozeMode) {
                // Not ICMPv6? -> Proceed to multicast filtering
                gen.addJumpIfR0NotEquals(IPPROTO_ICMPV6, dropAllIPv6MulticastsLabel);

                // ICMPv6 but not ECHO? -> Skip the multicast filter.
                // (ICMPv6 ECHO requests will go through the multicast filter below).
                gen.addLoad8intoR0(ICMP6_TYPE_OFFSET);
                gen.addJumpIfR0NotEquals(ICMPV6_ECHO_REQUEST_TYPE, skipIPv6MulticastFilterLabel);
            } else {
                gen.addJumpIfR0Equals(IPPROTO_ICMPV6, skipIPv6MulticastFilterLabel);
            }

            // Drop all other packets sent to ff00::/8 (multicast prefix).
            gen.defineLabel(dropAllIPv6MulticastsLabel);
            gen.addLoad8intoR0(IPV6_DEST_ADDR_OFFSET);
            gen.addCountAndDropIfR0Equals(0xff, DROPPED_IPV6_NON_ICMP_MULTICAST);
            // If any keepalive filter matches, drop
            generateV6KeepaliveFilters(gen);
            // Not multicast. Pass.
            gen.addCountAndPass(PASSED_IPV6_UNICAST_NON_ICMP);
            gen.defineLabel(skipIPv6MulticastFilterLabel);
        } else {
            generateV6KeepaliveFilters(gen);
            // If not ICMPv6, pass.
            gen.addCountAndPassIfR0NotEquals(IPPROTO_ICMPV6, PASSED_IPV6_NON_ICMP);
        }

        // If we got this far, the packet is ICMPv6.  Drop some specific types.
        // Not ICMPv6 NS -> skip.
        gen.addLoad8intoR0(ICMP6_TYPE_OFFSET); // warning: also used further below.
        if (enableNdOffload()) {
            final short skipNsPacketFilter = gen.getUniqueLabel();
            gen.addJumpIfR0NotEquals(ICMPV6_NEIGHBOR_SOLICITATION, skipNsPacketFilter);
            generateNsFilter((ApfV6GeneratorBase<?>) gen);
            // End of NS filter. generateNsFilter() method is terminal, so NS packet will be
            // either dropped or passed inside generateNsFilter().
            gen.defineLabel(skipNsPacketFilter);
        }

        if (enableIpv6PingOffload()) {
            generateUnicastIpv6PingOffload((ApfV6GeneratorBase<?>) gen);
        }

        // Add unsolicited multicast neighbor announcements filter
        short skipUnsolicitedMulticastNALabel = gen.getUniqueLabel();
        // Drop all router solicitations (b/32833400)
        gen.addCountAndDropIfR0Equals(ICMPV6_ROUTER_SOLICITATION, DROPPED_IPV6_ROUTER_SOLICITATION);
        // If not neighbor announcements, skip filter.
        gen.addJumpIfR0NotEquals(ICMPV6_NEIGHBOR_ADVERTISEMENT, skipUnsolicitedMulticastNALabel);
        // Drop all multicast NA to ff02::/120.
        // This is a way to cover ff02::1 and ff02::2 with a single JNEBS.
        // TODO: Drop only if they don't contain the address of on-link neighbours.
        final byte[] unsolicitedNaDropPrefix = Arrays.copyOf(IPV6_ALL_NODES_ADDRESS, 15);
        gen.addLoadImmediate(R0, IPV6_DEST_ADDR_OFFSET);
        gen.addJumpIfBytesAtR0NotEqual(unsolicitedNaDropPrefix, skipUnsolicitedMulticastNALabel);

        gen.addCountAndDrop(DROPPED_IPV6_MULTICAST_NA);
        gen.defineLabel(skipUnsolicitedMulticastNALabel);
    }

    /**
     * Creates the portion of an IGMP packet from the Ethernet source MAC address to the IPv4
     * Type of Service field.
     */
    private byte[] createIgmpPktFromEthSrcToIPv4Tos() {
        return CollectionUtils.concatArrays(
                mHardwareAddress,
                new byte[] {
                        // etherType: IPv4
                        (byte) 0x08, 0x00,
                        // version, IHL
                        (byte) 0x46,
                        // Tos: 0xC0 (ref: net/ipv4/igmp.c#igmp_send_report())
                        (byte) 0xc0}
        );
    }

    /**
     * Creates the portion of an IGMP packet from the IPv4 Identification field to the IPv4
     * Source Address.
     */
    private byte[] createIgmpPktFromIPv4IdToSrc() {
        final byte[] ipIdToSrc = new byte[] {
                // identification
                0, 0,
                // fragment flag
                (byte) (IPV4_FLAG_DF >> 8), 0,
                // TTL
                (byte) 1,
                // protocol
                (byte) IPV4_PROTOCOL_IGMP,
                // router alert option is { 0x94, 0x04, 0x00, 0x00 }, so we precalculate IPv4
                // checksum as 0x9404 + 0x0000 = 0x9404
                (byte) 0x94, (byte) 0x04
        };
        return CollectionUtils.concatArrays(
                ipIdToSrc,
                mIPv4Address
        );
    }

    /**
     * Creates IGMPv3 Membership Report packet payload (rfc3376#section-7.3.2).
     */
    private byte[] createIgmpV3ReportPayload() {
        final int groupNum = mIPv4McastAddrsExcludeAllHost.size();
        final byte[] igmpHeader = new byte[] {
                // IGMP type
                (byte) IPV4_IGMP_TYPE_V3_REPORT,
                // reserved
                0,
                // checksum, calculate later
                0, 0,
                // reserved
                0, 0,
                // num group records
                (byte) ((groupNum >> 8) & 0xff), (byte) (groupNum & 0xff)
        };
        final byte[] groupRecordHeader = new byte[] {
                // record type
                (byte) IGMPV3_MODE_IS_EXCLUDE,
                // aux data len,
                0,
                // num src
                0, 0
        };
        final byte[] payload =
                new byte[igmpHeader.length + groupNum * (groupRecordHeader.length + IPV4_ADDR_LEN)];
        int offset = 0;

        System.arraycopy(igmpHeader, 0, payload, offset, igmpHeader.length);
        offset += igmpHeader.length;
        for (Inet4Address mcastAddr: mIPv4McastAddrsExcludeAllHost) {
            System.arraycopy(groupRecordHeader, 0, payload, offset, groupRecordHeader.length);
            offset += groupRecordHeader.length;
            System.arraycopy(mcastAddr.getAddress(), 0, payload, offset, IPV4_ADDR_LEN);
            offset += IPV4_ADDR_LEN;
        }

        return payload;
    }

    /**
     * Generate transmit code to send IGMPv3 report in response to general query packets.
     */
    private void generateIgmpV3ReportTransmit(ApfV6GeneratorBase<?> gen,
            byte[] igmpPktFromEthSrcToIpTos, byte[] igmpPktFromIpIdToSrc)
            throws IllegalInstructionException {
        // We place template packet chunks in the data region first to reduce the number of
        // instructions needed for creating multiple IGMPv2 reports.
        // The following packet chunks can be used for creating both IGMPv2 and IGMPv3 reports:
        //   - from Ethernet source to IPv4 Tos: 10 bytes
        //   - from IPv4 identification to source address: 12 bytes
        final int igmpV2Ipv4TotalLen =
                IPV4_HEADER_MIN_LEN + IPV4_ROUTER_ALERT_OPTION_LEN + IPV4_IGMP_MIN_SIZE;
        final byte[] igmpV3ReportPayload = createIgmpV3ReportPayload();
        final byte[] igmpReportTemplate = CollectionUtils.concatArrays(
                ETH_MULTICAST_IGMP_V3_ALL_MULTICAST_ROUTERS_ADDRESS,
                igmpPktFromEthSrcToIpTos,
                new byte[] {
                        (byte) ((igmpV2Ipv4TotalLen >> 8) & 0xff),
                        (byte) (igmpV2Ipv4TotalLen & 0xff),
                },
                igmpPktFromIpIdToSrc,
                IPV4_ALL_IGMPV3_MULTICAST_ROUTERS_ADDRESS,
                IPV4_ROUTER_ALERT_OPTION,
                igmpV3ReportPayload
        );
        gen.maybeUpdateDataRegion(igmpReportTemplate);

        final int ipv4TotalLen = IPV4_HEADER_MIN_LEN
                + IPV4_ROUTER_ALERT_OPTION_LEN
                + IPV4_IGMP_MIN_SIZE
                + (mIPv4McastAddrsExcludeAllHost.size() * IPV4_IGMP_GROUP_RECORD_SIZE);
        final byte[] igmpV3FromEthDstToIpTos = CollectionUtils.concatArrays(
                ETH_MULTICAST_IGMP_V3_ALL_MULTICAST_ROUTERS_ADDRESS,
                igmpPktFromEthSrcToIpTos
        );
        final byte[] igmpV3PktFromIpIdToEnd = CollectionUtils.concatArrays(
                igmpPktFromIpIdToSrc,
                IPV4_ALL_IGMPV3_MULTICAST_ROUTERS_ADDRESS,
                IPV4_ROUTER_ALERT_OPTION,
                igmpV3ReportPayload
        );
        gen.addAllocate(ETHER_HEADER_LEN + ipv4TotalLen)
                .addDataCopy(igmpV3FromEthDstToIpTos)
                .addWriteU16(ipv4TotalLen)
                .addDataCopy(igmpV3PktFromIpIdToEnd)
                .addTransmitL4(
                        // ip_ofs
                        ETHER_HEADER_LEN,
                        // csum_ofs
                        IGMP_CHECKSUM_WITH_ROUTER_ALERT_OFFSET,
                        // csum_start
                        ETHER_HEADER_LEN + IPV4_HEADER_MIN_LEN + IPV4_ROUTER_ALERT_OPTION_LEN,
                        // partial_sum
                        0,
                        // udp
                        false
                )
                .addCountAndDrop(Counter.DROPPED_IGMP_V3_GENERAL_QUERY_REPLIED);
    }

    /**
     * Generate transmit code to send IGMPv2 report in response to general query packets.
     */
    private void generateIgmpV2ReportTransmit(ApfV6GeneratorBase<?> gen,
            byte[] igmpPktFromEthSrcToIpTos, byte[] igmpPktFromIpIdToSrc)
            throws IllegalInstructionException {
        final int ipv4TotalLen =
                IPV4_HEADER_MIN_LEN + IPV4_ROUTER_ALERT_OPTION_LEN + IPV4_IGMP_MIN_SIZE;
        final byte[] igmpV2PktFromEthSrcToIpSrc =  CollectionUtils.concatArrays(
                igmpPktFromEthSrcToIpTos,
                new byte[] {
                        (byte) ((ipv4TotalLen >> 8) & 0xff), (byte) (ipv4TotalLen & 0xff),
                },
                igmpPktFromIpIdToSrc
        );
        for (Inet4Address mcastAddr: mIPv4McastAddrsExcludeAllHost) {
            final MacAddress mcastEther =
                    NetworkStackUtils.ipv4MulticastToEthernetMulticast(mcastAddr);
            gen.addAllocate(ETHER_HEADER_LEN + ipv4TotalLen)
                    .addDataCopy(mcastEther.toByteArray())
                    .addDataCopy(igmpV2PktFromEthSrcToIpSrc)
                    .addDataCopy(mcastAddr.getAddress())
                    .addDataCopy(IGMPV2_REPORT_FROM_IPV4_OPTION_TO_IGMP_CHECKSUM)
                    .addDataCopy(mcastAddr.getAddress())
                    .addTransmitL4(
                            // ip_ofs
                            ETHER_HEADER_LEN,
                            // csum_ofs
                            IGMP_CHECKSUM_WITH_ROUTER_ALERT_OFFSET,
                            // csum_start
                            ETHER_HEADER_LEN + IPV4_HEADER_MIN_LEN + IPV4_ROUTER_ALERT_OPTION_LEN,
                            // partial_sum
                            0,
                            // udp
                            false
                    );
        }

        gen.addCountAndDrop(Counter.DROPPED_IGMP_V2_GENERAL_QUERY_REPLIED);
    }

    /**
     * Generates filter code to handle IGMP packets.
     * <p>
     * On entry, this filter know it is processing an IPv4 packet. It will then process all IGMP
     * packets, either passing or dropping them. Non-IGMP packets are skipped.
     */
    private void generateIgmpFilter(ApfV6GeneratorBase<?> v6Gen)
            throws IllegalInstructionException {
        final short skipIgmpFilter = v6Gen.getUniqueLabel();
        final short checkIgmpV1orV2 = v6Gen.getUniqueLabel();

        // Check 1) it's not a fragment. 2) it's IGMP.
        v6Gen.addJumpIfNotUnfragmentedIPv4Protocol(IPV4_PROTOCOL_IGMP, skipIgmpFilter);

        // Calculate the IPv4 payload length: (total length - IPv4 header length).
        // Memory slot 0 is occupied temporarily to store the length.
        v6Gen.addLoad16intoR0(IPV4_TOTAL_LENGTH_OFFSET)
                .addLoadFromMemory(R1, MemorySlot.IPV4_HEADER_SIZE)
                .addNeg(R1)
                .addAddR1ToR0()
                .addStoreToMemory(MemorySlot.SLOT_0, R0);

        // If payload length is less than 8 or equal to 9, 10, 11, it's invalid IGMP packet: drop.
        v6Gen.addCountAndDropIfR0LessThan(IPV4_IGMP_MIN_SIZE, DROPPED_IGMP_INVALID)
                .addCountAndDropIfR0IsOneOf(Set.of(9L, 10L, 11L), DROPPED_IGMP_INVALID);

        // If it's an IGMPv1/IGMPv2/IGMPv3 report: drop.
        // A host normally cancels its own pending report if it observes
        // an identical report from another host on the network (host suppression).
        // While dropping reports here technically disrupts this host's suppression behavior,
        // it is acceptable since other devices on the network will perform the suppression.
        // If the IGMP type is not one of the reports, it's either a query(type=0x11) or an
        // invalid packet.
        v6Gen.addLoadFromMemory(R1, MemorySlot.IPV4_HEADER_SIZE)
                .addLoad8R1IndexedIntoR0(ETHER_HEADER_LEN)
                .addCountAndDropIfR0IsOneOf(IGMP_TYPE_REPORTS, DROPPED_IGMP_REPORT)
                .addCountAndDropIfR0NotEquals(IPV4_IGMP_TYPE_QUERY, DROPPED_IGMP_INVALID);

        // If group address is not 0.0.0.0, it's an IGMPv2/v3 group specific query: pass.
        // rfc3376#section-6.1 mentions group specific queries are sent when a router receives a
        // State-Change record indicating a system is leaving a group. Therefore, since the
        // router only sends group-specific queries after receiving a leave message, it is not
        // sent out periodically.
        // Increased APF bytecode size for offloading these queries may not yield significant
        // power benefits. In this case, letting the kernel handle group-specific queries is
        // acceptable.
        v6Gen.addLoad32R1IndexedIntoR0(IGMP_MULTICAST_ADDRESS_OFFSET)
                .addCountAndPassIfR0NotEquals(0 /* 0.0.0.0 */, PASSED_IPV4);

        // If we reach here, we know it is an IGMPv1/IGMPv2/IGMPv3 general query.

        // The general query IPv4 destination address must be 224.0.0.1.
        v6Gen.addLoad32intoR0(IPV4_DEST_ADDR_OFFSET)
                .addCountAndDropIfR0NotEquals(IPV4_ALL_HOSTS_ADDRESS_IN_LONG,
                        DROPPED_IGMP_INVALID);

        // Check payload length, since invalid length already checked,
        // it should be 8 (IGMPv1 or IGMPv2) or >=12 (IGMPv3)
        v6Gen.addLoadFromMemory(R0, MemorySlot.SLOT_0)
                .addJumpIfR0Equals(IPV4_IGMP_MIN_SIZE, checkIgmpV1orV2);

        // ===== IGMPv3 general query =====
        // To optimize for bytecode size, the IGMPv3 report is constructed first.
        // Its packet structure is then reused as a template when creating the IGMPv2 report.
        final byte[] igmpPktFromEthSrcToIpTos = createIgmpPktFromEthSrcToIPv4Tos();
        final byte[] igmpPktFromIpIdToSrc = createIgmpPktFromIPv4IdToSrc();
        generateIgmpV3ReportTransmit(v6Gen, igmpPktFromEthSrcToIpTos, igmpPktFromIpIdToSrc);

        // ===== IGMPv1 or IGMPv2 general query =====
        v6Gen.defineLabel(checkIgmpV1orV2);
        // Based on rfc3376#section-7.1 If max resp time is 0, it's IGMPv1: pass.
        // We don't expect many networks are still using IGMPv1, pass it to the kernel to save
        // bytecode size.
        // (Note: R1 is still IPV4_HEADER_SIZE)
        v6Gen.addLoad8R1IndexedIntoR0(IGMP_MAX_RESP_TIME_OFFSET)
                .addCountAndPassIfR0Equals(0, PASSED_IPV4); // IGMPv1

        // Drop and transmit IGMPv2 reports
        generateIgmpV2ReportTransmit(v6Gen, igmpPktFromEthSrcToIpTos, igmpPktFromIpIdToSrc);

        v6Gen.defineLabel(skipIgmpFilter);
    }

    /**
     * Creates MLDv1 Listener Report packet message (rfc2710#section-3).
     */
    private byte[] createMldV1ReportMessage(final Inet6Address mcastAddr) {
        final byte[] mldv1Header = new byte[] {
            // MLD type
            (byte) IPV6_MLD_TYPE_V1_REPORT,
            // code
            0,
            // hop-by-hop option is { 0x3a, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00 }
            // so we precalculate MLD checksum as follows:
            // 0xffff - (0x3a00 + 0x0502 + 0x0000 + 0x0100) = 0xbffd
            (byte) 0xbf, (byte) 0xfd,
            // max response delay
            0, 0,
            // reserved
            0, 0
        };

        return CollectionUtils.concatArrays(mldv1Header, mcastAddr.getAddress());
    }

    /**
     * Creates MLDv2 Listener Report packet payload (rfc3810#section-5.2).
     */
    private byte[] createMldV2ReportPayload() {
        final int mcastAddrsNum = mIPv6McastAddrsExcludeAllHost.size();
        final byte[] mldHeader = new byte[] {
            // MLD type
            (byte) IPV6_MLD_TYPE_V2_REPORT,
            // code
            0,
            // hop-by-hop option is { 0x3a, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00 }
            // so we precalculate MLD checksum as follows:
            // 0xffff - (0x3a00 + 0x0502 + 0x0000 + 0x0100) = 0xbffd
            (byte) 0xbf, (byte) 0xfd,
            // reserved
            0, 0,
            // num of multicast address records
            (byte) ((mcastAddrsNum >> 8) & 0xff), (byte) (mcastAddrsNum & 0xff)
        };

        final byte[] mcastRecordHeader = new byte[] {
            // record type
            (byte) MLD2_MODE_IS_EXCLUDE,
            // aux data len,
            0,
            // num src
            0, 0
        };

        final byte[] payload =
                new byte[
                    mldHeader.length + mcastAddrsNum * IPV6_MLD_V2_MULTICAST_ADDRESS_RECORD_SIZE
                ];
        int offset = 0;

        System.arraycopy(mldHeader, 0, payload, offset, mldHeader.length);
        offset += mldHeader.length;
        for (Inet6Address mcastAddr: mIPv6McastAddrsExcludeAllHost) {
            System.arraycopy(mcastRecordHeader, 0, payload, offset, mcastRecordHeader.length);
            offset += mcastRecordHeader.length;
            System.arraycopy(mcastAddr.getAddress(), 0, payload, offset, IPV6_ADDR_LEN);
            offset += IPV6_ADDR_LEN;
        }

        return payload;
    }

    /**
     * Creates the portion of an MLD packet from the Ethernet source MAC address to the IPv6
     * VTF field.
     */
    private byte[] createMldPktFromEthSrcToIPv6Vtf() {
        return CollectionUtils.concatArrays(
            mHardwareAddress,
            new byte[] {
                // etherType: IPv6
                (byte) 0x86, (byte) 0xdd,
                // version, traffic class, flow label
                // 0x60000000 (ref: net/ipv6/mcast.c#ip6_mc_hdr())
                (byte) 0x60, 0, 0, 0}
        );
    }

    /**
     * Creates the portion of an MLD packet from the IPv6 Next Header to the IPv6 Source Address.
     */
    private byte[] createMldPktFromIPv6NextHdrToSrc() {
        final byte[] ipv6FromNextHdrToHoplimit = new byte[] {
            // Next header: HOPOPTS
            0,
            // Hop limit
            (byte) 1
        };
        return CollectionUtils.concatArrays(
            ipv6FromNextHdrToHoplimit,
            mIPv6LinkLocalAddress.getAddress()
        );
    }

    /**
     * Generate transmit code to send MLDv1 report in response to general query packets.
     */
    private void generateMldV1ReportTransmit(ApfV6GeneratorBase<?> gen,
            byte[] mldPktFromEthSrcToIpv6Vtf, byte[] mldPktFromIpv6NextHdrToSrc)
            throws IllegalInstructionException {
        // Reuse MLDv2 packet chunks when creating the MLDv1 report listed below:
        //   - from Ethernet source to IPv6 VTF: 12 bytes
        //   - from IPv6 next header to source address: 18 bytes
        final int packetSize =
                ETHER_HEADER_LEN
                + IPV6_HEADER_LEN
                + IPV6_MLD_HOPOPTS.length
                + IPV6_MLD_V1_MESSAGE_SIZE;
        for (Inet6Address mcastAddr: mIPv6McastAddrsExcludeAllHost) {
            final MacAddress mcastEther =
                    NetworkStackUtils.ipv6MulticastToEthernetMulticast(mcastAddr);
            gen.addAllocate(packetSize)
                    .addDataCopy(mcastEther.toByteArray())
                    .addDataCopy(mldPktFromEthSrcToIpv6Vtf)
                    .addWriteU16(IPV6_MLD_HOPOPTS.length + IPV6_MLD_V1_MESSAGE_SIZE)
                    .addDataCopy(mldPktFromIpv6NextHdrToSrc)
                    .addDataCopy(mcastAddr.getAddress())
                    .addDataCopy(IPV6_MLD_HOPOPTS)
                    .addDataCopy(createMldV1ReportMessage(mcastAddr))
                    .addTransmitL4(
                        // ip_ofs
                        ETHER_HEADER_LEN,
                        // csum_ofs
                        IPV6_MLD_CHECKSUM_OFFSET,
                        // csum_start
                        IPV6_SRC_ADDR_OFFSET,
                        // partial_sum
                        IPPROTO_ICMPV6 + IPV6_MLD_V1_MESSAGE_SIZE,
                        // udp
                        false
                    );
        }

        gen.addCountAndDrop(DROPPED_IPV6_MLD_V1_GENERAL_QUERY_REPLIED);
    }

    /**
     * Generate transmit code to send MLDv2 report in response to general query packets.
     */
    private void generateMldV2ReportTransmit(ApfV6GeneratorBase<?> gen,
            byte[] mldPktFromEthSrcToIpv6Vtf, byte[] mldPktFromIpv6NextHdrToSrc)
            throws IllegalInstructionException {
        final int mcastAddrsNum = mIPv6McastAddrsExcludeAllHost.size();
        final int ipv6PayloadLength = IPV6_MLD_HOPOPTS.length
                + IPV6_MLD_MESSAGE_MIN_SIZE
                + (mcastAddrsNum * IPV6_MLD_V2_MULTICAST_ADDRESS_RECORD_SIZE);
        final byte[] encodedIPv6PayloadLength = {
            (byte) ((ipv6PayloadLength >> 8) & 0xff), (byte) (ipv6PayloadLength & 0xff),
        };
        final byte[] packet = CollectionUtils.concatArrays(
            ETH_MULTICAST_MLD_V2_ALL_MULTICAST_ROUTERS_ADDRESS,
            mldPktFromEthSrcToIpv6Vtf,
            encodedIPv6PayloadLength,
            mldPktFromIpv6NextHdrToSrc,
            IPV6_MLD_V2_ALL_ROUTERS_MULTICAST_ADDRESS,
            IPV6_MLD_HOPOPTS,
            createMldV2ReportPayload()
        );

        gen.addAllocate(ETHER_HEADER_LEN + IPV6_HEADER_LEN + ipv6PayloadLength)
            .addDataCopy(packet)
            .addTransmitL4(
                // ip_ofs
                ETHER_HEADER_LEN,
                // csum_ofs
                IPV6_MLD_CHECKSUM_OFFSET,
                // csum_start
                IPV6_SRC_ADDR_OFFSET,
                // partial_sum
                IPPROTO_ICMPV6 + (ipv6PayloadLength - IPV6_MLD_HOPOPTS.length),
                // udp
                false
            ).addCountAndDrop(DROPPED_IPV6_MLD_V2_GENERAL_QUERY_REPLIED);
    }

    /**
     * Generates filter code to handle MLD packets.
     * <p>
     * On entry, this filter knows it is processing an IPv6 packet. It will then process all MLD
     * packets, either passing or dropping them. Non-MLD packets are skipped.
     * R0 contains the u8 IPv6 next header.
     */
    private void generateMldFilter(ApfV6GeneratorBase<?> gen)
            throws IllegalInstructionException {
        final short skipMldFilter = gen.getUniqueLabel();
        final short checkMldv1 = gen.getUniqueLabel();

        // If next header is not hop-by-hop, then skip
        gen.addJumpIfR0NotEquals(IPPROTO_HOPOPTS, skipMldFilter);

        final int mldPacketMinSize =
                ETHER_HEADER_LEN + IPV6_HEADER_LEN + IPV6_MLD_HOPOPTS.length + IPV6_MLD_MIN_SIZE;
        // If packet is too small to be MLD packet, then skip
        gen.addLoadFromMemory(R0, MemorySlot.PACKET_SIZE)
                .addJumpIfR0LessThan(mldPacketMinSize, skipMldFilter)
                .addSub(ETHER_HEADER_LEN + IPV6_HEADER_LEN + IPV6_MLD_HOPOPTS.length)
                // Memory slot 0 is occupied temporarily to store the MLD payload length.
                .addStoreToMemory(MemorySlot.SLOT_0, R0);

        // If the hop-by-hop option is not the one used by MLD, then skip
        gen.addLoadImmediate(R0, IPV6_EXT_HEADER_OFFSET)
                .addJumpIfBytesAtR0NotEqual(IPV6_MLD_HOPOPTS, skipMldFilter);

        // If the packet is an MLDv1 report or done, or an MLDv2 report, then drop it.
        // Else if the packet is not an MLD query packet, then skip.
        gen.addLoad8intoR0(IPV6_MLD_TYPE_OFFSET)
                .addCountAndDropIfR0IsOneOf(IPV6_MLD_TYPE_REPORTS, DROPPED_IPV6_MLD_REPORT)
                .addJumpIfR0NotEquals(IPV6_MLD_TYPE_QUERY, skipMldFilter);

        // If we reach here, we know it is an MLDv1/MLDv2 query.

        // If the payload length is 25, 26, or 27, the MLD packet is invalid and should be dropped.
        gen.addLoadFromMemory(R0, MemorySlot.SLOT_0)
                .addCountAndDropIfR0IsOneOf(Set.of(25L, 26L, 27L), DROPPED_IPV6_MLD_INVALID);

        // rfc3810#section-5 and rfc2710#section-3 describe that all MLD messages are sent with a
        // link-local IPv6 source address, an IPv6 Hop Limit of 1, and an IPv6 Router Alert
        // option [RTR-ALERT] in a Hop-by-Hop Options header.
        // rfc3810#section-5.2.13 describes that an MLDv2 Report MUST be sent with a valid
        // IPv6 link-local source address, or the unspecified address (::), if the sending interface
        // has not yet acquired a valid link-local address.
        // Its OK to not check :: here since we also drop MLD reports.
        // If the source address is a not a link-local address, then drop.
        gen.addLoad16intoR0(IPV6_SRC_ADDR_OFFSET)
                .addCountAndDropIfR0NotEquals(0xfe80, DROPPED_IPV6_MLD_INVALID);

        // If hop limit is not 1, then drop.
        gen.addLoad8intoR0(IPV6_HOP_LIMIT_OFFSET)
                .addCountAndDropIfR0NotEquals(1, DROPPED_IPV6_MLD_INVALID);

        // If the multicast address is not "::", it is an MLD2 multicast-address-specific query,
        // then pass.
        gen.addLoadImmediate(R0, IPV6_MLD_MULTICAST_ADDR_OFFSET)
                .addCountAndPassIfBytesAtR0NotEqual(IPV6_ADDR_ANY.getAddress(), PASSED_IPV6_ICMP);

        // If we reach here, we know it is an MLDv1/MLDv2 general query.

        // The general query IPv6 destination address must be ff02::1.
        gen.addLoadImmediate(R0, IPV6_DEST_ADDR_OFFSET)
                .addCountAndDropIfBytesAtR0NotEqual(IPV6_ALL_NODES_ADDRESS,
                        DROPPED_IPV6_MLD_INVALID);

        // If the MLD payload length is 24, it is an MLDv1 packet, otherwise, it is an MLDv2 packet.
        gen.addLoadFromMemory(R0, MemorySlot.SLOT_0)
                .addJumpIfR0Equals(IPV6_MLD_MIN_SIZE, checkMldv1);

        // ===== MLDv2 general query =====
        // To optimize for bytecode size, the MLDv2 report is constructed first.
        // Its packet structure is then reused as a template when creating the IGMPv1 report.
        final byte[] mldPktFromEthSrcToIPv6Vtf = createMldPktFromEthSrcToIPv6Vtf();
        final byte[] mldPktFromIPv6NextHdrToSrc = createMldPktFromIPv6NextHdrToSrc();
        generateMldV2ReportTransmit(gen, mldPktFromEthSrcToIPv6Vtf, mldPktFromIPv6NextHdrToSrc);

        gen.defineLabel(checkMldv1);
        // ===== MLDv1 general query =====
        generateMldV1ReportTransmit(gen, mldPktFromEthSrcToIPv6Vtf, mldPktFromIPv6NextHdrToSrc);

        gen.defineLabel(skipMldFilter);
    }

    /**
     * Generate filter code to drop IPv4 TCP packets on port 7.
     * <p>
     * On entry, we know it is IPv4 ethertype, but don't know anything else.
     * R0/R1 have nothing useful in them, and can be clobbered.
     */
    private void generateV4TcpPort7Filter(ApfV4GeneratorBase<?> gen)
            throws IllegalInstructionException {
        final short skipPort7V4Filter = gen.getUniqueLabel();

        // Check it's TCP.
        gen.addLoad8intoR0(IPV4_PROTOCOL_OFFSET);
        gen.addJumpIfR0NotEquals(IPPROTO_TCP, skipPort7V4Filter);

        // Check it's not a fragment or is the initial fragment.
        gen.addLoad16intoR0(IPV4_FRAGMENT_OFFSET_OFFSET);
        gen.addJumpIfR0AnyBitsSet(IPV4_FRAGMENT_OFFSET_MASK, skipPort7V4Filter);

        // Check it's destination port 7.
        gen.addLoadFromMemory(R1, MemorySlot.IPV4_HEADER_SIZE);
        gen.addLoad16R1IndexedIntoR0(TCP_UDP_DESTINATION_PORT_OFFSET);
        gen.addJumpIfR0NotEquals(ECHO_PORT, skipPort7V4Filter);

        // Drop it.
        gen.addCountAndDrop(DROPPED_IPV4_TCP_PORT7_UNICAST);

        // Skip label.
        gen.defineLabel(skipPort7V4Filter);
    }

    private void generateV6KeepaliveFilters(ApfV4GeneratorBase<?> gen)
            throws IllegalInstructionException {
        generateKeepaliveFilters(gen, TcpKeepaliveAckV6.class, IPPROTO_TCP, IPV6_NEXT_HEADER_OFFSET,
                gen.getUniqueLabel());
    }

    private byte[] createMdns4PktFromEthDstToIPv4Tos(boolean enabled) {
        if (!enabled) {
            return null;
        }
        return concatArrays(
                ETH_MULTICAST_MDNS_V4_MAC_ADDRESS,
                mHardwareAddress,
                new byte[]{
                        0x08, 0x00, // ethertype: IPv4
                        0x45, 0x00, // version, IHL, DSCP, ECN,
                });
    }

    private byte[] createMdns6PktFromEthDstToIPv6FlowLabel(boolean enabled) {
        if (!enabled) {
            return null;
        }
        return concatArrays(
                ETH_MULTICAST_MDNS_V6_MAC_ADDRESS,
                mHardwareAddress,
                new byte[]{
                        (byte) 0x86, (byte) 0xdd, // ethertype: IPv6
                        0x60, 0x00, 0x00, 0x00, // version, traffic class, flow label
                });
    }


    private byte[] createMdns4PktFromIPv4IdToUdpDport(boolean enabled) {
        if (!enabled) {
            return null;
        }
        return concatArrays(
                new byte[]{
                        0x00, 0x00, // identification
                        (byte) (IPV4_FLAG_DF >> 8), 0, // flags, fragment offset
                        (byte) 0xff, // set TTL to 255 per rfc6762#section-11
                        (byte) IPPROTO_UDP,
                        0x00, 0x00, // checksum, it's a placeholder that will be filled in later.
                },
                mIPv4Address,
                MDNS_IPV4_ADDR,
                MDNS_PORT_IN_BYTES, // source port
                MDNS_PORT_IN_BYTES); // destination port
    }

    private byte[] createMdns6PktFromIPv6NextHdrToUdpDport(boolean enabled) {
        if (!enabled) {
            return null;
        }
        return concatArrays(
                new byte[]{
                        (byte) IPPROTO_UDP,
                        (byte) 0xff, // set hop limit to 255 per rfc6762#section-11
                },
                mIPv6LinkLocalAddress.getAddress(),
                MDNS_IPV6_ADDR,
                MDNS_PORT_IN_BYTES, // source port
                MDNS_PORT_IN_BYTES); // destination port
    }

    /**
     * Generates filter code to process an mDNS payload against offload rules.
     * The generated filter code is guaranteed to process all IPv4 and IPv6 mDNS packets,
     * ensuring each packet is either passed or dropped.
     * <p>
     * The only way to enter the mDNS offload payload check logic is by jumping to the
     * labelCheckMdnsQueryPayload label.
     * On entry, the packet is known to be an IPv4/IPv6 mDNS query packet, and register R1
     * is set to the offset of the beginning of the UDP payload (the DNS header).
     *
     * @param gen the APF generator to generate the filter code
     * @param labelCheckMdnsQueryPayload the label to jump to for checking the mDNS query payload
     */
    private void generateMdnsQueryOffload(ApfV6GeneratorBase<?> gen,
            short labelCheckMdnsQueryPayload)
            throws IllegalInstructionException {
        // The mDNS payload check logic is terminal; the program will always result in either
        // PASS or DROP.
        gen.defineLabel(labelCheckMdnsQueryPayload);
        // TODO: Implement failover logic for insufficient APF RAM to offload all records. When
        //  APF RAM is not enough, rules with lower priority should be transitioned to passthrough
        //  mode (e.g., if a QNAME matches, the packet should be passed). If RAM remains
        //  insufficient even with all rules in passthrough mode, the mDNS filter should fail open.

        // Set R0 to the offset of the beginning of the UDP payload (the DNS header)
        gen.addSwap();

        final boolean enableMdns4 = enableMdns4Offload();
        final boolean enableMdns6 = enableMdns6Offload();
        final byte[] mdns4EthDstToTos = createMdns4PktFromEthDstToIPv4Tos(enableMdns4);
        final byte[] mdns4IdToUdpDport = createMdns4PktFromIPv4IdToUdpDport(enableMdns4);
        final byte[] mdns6EthDstToFlowLabel = createMdns6PktFromEthDstToIPv6FlowLabel(enableMdns6);
        final byte[] mdns6NextHdrToUdpDport = createMdns6PktFromIPv6NextHdrToUdpDport(enableMdns6);

        for (MdnsOffloadRule rule : mOffloadRules) {
            final short ruleNotMatch = gen.getUniqueLabel();
            final short ruleMatch = gen.getUniqueLabel();
            final short offloadIPv6Mdns = gen.getUniqueLabel();

            for (MdnsOffloadRule.Matcher matcher : rule.mMatchers) {
                try {
                    gen.addJumpIfPktAtR0ContainDnsQ(matcher.mQnames, matcher.mQtypes, ruleMatch);
                } catch (IllegalArgumentException e) {
                    Log.e(TAG, "Failed to generate mDNS offload filter for rule: " + rule, e);
                }
            }

            gen.addJump(ruleNotMatch);

            gen.defineLabel(ruleMatch);

            // If there is no offload payload, pass the packet to let NsdService handle it.
            if (rule.mOffloadPayload == null) {
                gen.addCountAndPass(PASSED_MDNS);
            } else {
                if (enableMdns4 && enableMdns6) {
                    gen.addLoad16intoR0(ETH_ETHERTYPE_OFFSET)
                            .addJumpIfR0NotEquals(ETH_P_IP, offloadIPv6Mdns);
                }

                if (enableMdns4) {
                    final int udpLength = UDP_HEADER_LEN + rule.mOffloadPayload.length;
                    final int ipv4TotalLength = IPV4_HEADER_MIN_LEN + udpLength;
                    final int pktLength = ETH_HEADER_LEN + ipv4TotalLength;

                    gen.addAllocate(pktLength)
                            .addDataCopy(mdns4EthDstToTos)
                            .addWriteU16(ipv4TotalLength)
                            .addDataCopy(mdns4IdToUdpDport)
                            .addWrite32(udpLength << 16) // udp length and checksum
                            .addDataCopy(rule.mOffloadPayload)
                            .addTransmitL4(
                                    ETH_HEADER_LEN, // ip_ofs
                                    IPV4_UDP_DESTINATION_CHECKSUM_NO_OPTIONS_OFFSET, // csum_ofs
                                    IPV4_SRC_ADDR_OFFSET, // csum_start
                                    IPPROTO_UDP + udpLength, // partial_sum
                                    true // udp
                            ).addCountAndDrop(Counter.DROPPED_MDNS_REPLIED);
                }

                if (enableMdns4 && enableMdns6) {
                    gen.defineLabel(offloadIPv6Mdns);
                }

                if (enableMdns6) {
                    final int udpLength = UDP_HEADER_LEN + rule.mOffloadPayload.length;
                    final int pktLength = ETH_HEADER_LEN + IPV6_HEADER_LEN + udpLength;
                    gen.addAllocate(pktLength)
                            .addDataCopy(mdns6EthDstToFlowLabel)
                            .addWriteU16(udpLength) // payload length
                            .addDataCopy(mdns6NextHdrToUdpDport)
                            .addWrite32(udpLength << 16) //  udp length and checksum
                            .addDataCopy(rule.mOffloadPayload)
                            .addTransmitL4(
                                    ETH_HEADER_LEN, // ip_ofs
                                    IPV6_UDP_DESTINATION_CHECKSUM_OFFSET, // csum_ofs
                                    IPV6_SRC_ADDR_OFFSET, // csum_start
                                    IPPROTO_UDP + udpLength, // partial_sum
                                    true // udp
                            ).addCountAndDrop(Counter.DROPPED_MDNS_REPLIED);
                }
            }

            gen.defineLabel(ruleNotMatch);
        }

        // If no offload rules match, we should still respect the multicast filter. During the
        // transition period, not all apps will use NsdManager for mDNS advertising. If an app
        // decides to perform mDNS advertising itself, it must acquire a multicast lock, and no
        // offload rules will be registered for that app. In this case, the APF should pass the
        // mDNS packet and allow the app to handle the query.
        if (mMulticastFilter) {
            gen.addCountAndDrop(DROPPED_MDNS);
        } else {
            gen.addCountAndPass(PASSED_MDNS);
        }
    }

    /**
     * Begin generating an APF program to:
     * <ul>
     * <li>Drop/Pass 802.3 frames (based on policy)
     * <li>Drop packets with EtherType within the Black List
     * <li>Drop ARP requests not for us, if mIPv4Address is set,
     * <li>Drop IPv4 broadcast packets, except DHCP destined to our MAC,
     * <li>Drop IPv4 multicast packets, if mMulticastFilter,
     * <li>Pass all other IPv4 packets,
     * <li>Drop all broadcast non-IP non-ARP packets.
     * <li>Pass all non-ICMPv6 IPv6 packets,
     * <li>Pass all non-IPv4 and non-IPv6 packets,
     * <li>Drop IPv6 ICMPv6 NAs to anything in ff02::/120.
     * <li>Drop IPv6 ICMPv6 RSs.
     * <li>Filter IPv4 packets (see generateIPv4Filter())
     * <li>Filter IPv6 packets (see generateIPv6Filter())
     * <li>Let execution continue off the end of the program for IPv6 ICMPv6 packets. This allows
     *     insertion of RA filters here, or if there aren't any, just passes the packets.
     * </ul>
     * @param gen the APF generator to generate the filter code
     * @param labelCheckMdnsQueryPayload the label to jump to for checking the mDNS query payload
     */
    private void emitPrologue(@NonNull ApfV4GeneratorBase<?> gen, short labelCheckMdnsQueryPayload)
            throws IllegalInstructionException {
        if (hasDataAccess(mApfVersionSupported)) {
            if (gen instanceof ApfV4Generator) {
                // Increment TOTAL_PACKETS.
                // Only needed in APFv4.
                // In APFv6, the interpreter will increase the counter on packet receive.
                gen.addIncrementCounter(TOTAL_PACKETS);
            }

            gen.addLoadFromMemory(R0, MemorySlot.FILTER_AGE_SECONDS);
            gen.addStoreCounter(FILTER_AGE_SECONDS, R0);

            // requires a new enough APFv5+ interpreter, otherwise will be 0
            gen.addLoadFromMemory(R0, MemorySlot.FILTER_AGE_16384THS);
            gen.addStoreCounter(FILTER_AGE_16384THS, R0);

            // requires a new enough APFv5+ interpreter, otherwise will be 0
            gen.addLoadFromMemory(R0, MemorySlot.APF_VERSION);
            gen.addStoreCounter(APF_VERSION, R0);

            // store this program's sequential id, for later comparison
            gen.addLoadImmediate(R0, mNumProgramUpdates);
            gen.addStoreCounter(APF_PROGRAM_ID, R0);
        }

        // Here's a basic summary of what the initial program does:
        //
        // if it is a loopback (src mac is nic's primary mac) packet
        //    if 25Q2+:
        //      drop
        //    else
        //      pass
        // if it's a 802.3 Frame (ethtype < 0x0600):
        //    drop or pass based on configurations
        // if it has a ether-type that belongs to the black list
        //    drop
        // if it's ARP:
        //   insert ARP filter to drop or pass these appropriately
        // if it's IPv4:
        //   insert IPv4 filter to drop or pass these appropriately
        // if it's not IPv6:
        //   if it's broadcast:
        //     drop
        //   pass
        // insert IPv6 filter to drop, pass, or fall off the end for ICMPv6 packets

        gen.addLoadImmediate(R0, ETHER_SRC_ADDR_OFFSET);
        if (NetworkStackUtils.isAtLeast25Q2()) {
            gen.addCountAndDropIfBytesAtR0Equal(mHardwareAddress, DROPPED_ETHER_OUR_SRC_MAC);
        } else {
            gen.addCountAndPassIfBytesAtR0Equal(mHardwareAddress, PASSED_ETHER_OUR_SRC_MAC);
        }

        gen.addLoad16intoR0(ETH_ETHERTYPE_OFFSET);
        if (SdkLevel.isAtLeastV()) {
            // IPv4, ARP, IPv6, EAPOL, WAPI
            gen.addCountAndDropIfR0IsNoneOf(Set.of(0x0800L, 0x0806L, 0x86DDL, 0x888EL, 0x88B4L),
                    DROPPED_ETHERTYPE_NOT_ALLOWED);
        } else  {
            if (mDrop802_3Frames) {
                // drop 802.3 frames (ethtype < 0x0600)
                gen.addCountAndDropIfR0LessThan(ETH_TYPE_MIN, DROPPED_802_3_FRAME);
            }
            // Handle ether-type black list
            if (mEthTypeBlackList.length > 0) {
                final Set<Long> deniedEtherTypes = new ArraySet<>();
                for (int p : mEthTypeBlackList) {
                    deniedEtherTypes.add((long) p);
                }
                gen.addCountAndDropIfR0IsOneOf(deniedEtherTypes, DROPPED_ETHERTYPE_NOT_ALLOWED);
            }
        }

        // Add ARP filters:
        short skipArpFiltersLabel = gen.getUniqueLabel();
        gen.addJumpIfR0NotEquals(ETH_P_ARP, skipArpFiltersLabel);
        generateArpFilter(gen);
        gen.defineLabel(skipArpFiltersLabel);

        gen.addLoad16intoR0(ETH_ETHERTYPE_OFFSET);

        // Add IPv4 filters:
        short skipIPv4FiltersLabel = gen.getUniqueLabel();
        gen.addJumpIfR0NotEquals(ETH_P_IP, skipIPv4FiltersLabel);
        generateIPv4Filter(gen, labelCheckMdnsQueryPayload);
        gen.defineLabel(skipIPv4FiltersLabel);

        // Check for IPv6:
        // NOTE: Relies on R0 containing ethertype. This is safe because if we got here, we did
        // not execute the IPv4 filter, since this filter do not fall through, but either drop or
        // pass.
        short ipv6FilterLabel = gen.getUniqueLabel();
        gen.addJumpIfR0Equals(ETH_P_IPV6, ipv6FilterLabel);

        // Drop non-IP non-ARP broadcasts, pass the rest
        gen.addLoadImmediate(R0, ETH_DEST_ADDR_OFFSET);
        gen.addCountAndPassIfBytesAtR0NotEqual(ETHER_BROADCAST, PASSED_NON_IP_UNICAST);
        gen.addCountAndDrop(DROPPED_ETH_BROADCAST);

        // Add IPv6 filters:
        gen.defineLabel(ipv6FilterLabel);
        generateIPv6Filter(gen, labelCheckMdnsQueryPayload);
    }

    /**
     * Append packet counting epilogue to the APF program.
     * <p>
     * Currently, the epilogue consists of two trampolines which count passed and dropped packets
     * before jumping to the actual PASS and DROP labels.
     */
    private void emitEpilogue(ApfV4GeneratorBase<?> gen) throws IllegalInstructionException {
        // Execution will reach here if none of the filters match, which will pass the packet to
        // the application processor.
        gen.addCountAndPass(PASSED_IPV6_ICMP);

        // TODO: merge the addCountTrampoline() into generate() method
        gen.addCountTrampoline();
    }

    private String getApfConfigMessage() {
        final StringBuilder sb = new StringBuilder();
        sb.append("{ ");
        sb.append("mcast: ");
        sb.append(mMulticastFilter ? "DROP" : "ALLOW");
        sb.append(", ");
        sb.append("offloads: ");
        sb.append("[ ");
        if (enableArpOffload()) {
            sb.append("ARP, ");
        }
        if (enableNdOffload()) {
            sb.append("ND, ");
        }
        if (enableIgmpOffload()) {
            sb.append("IGMP, ");
        }
        if (enableMldOffload()) {
            sb.append("MLD, ");
        }
        if (enableIpv4PingOffload()) {
            sb.append("Ping4, ");
        }
        if (enableIpv6PingOffload()) {
            sb.append("Ping6, ");
        }
        if (enableMdns4Offload()) {
            sb.append("Mdns4, ");
        }
        if (enableMdns6Offload()) {
            sb.append("Mdns6, ");
        }
        sb.append("] ");
        sb.append("total RAs: ");
        sb.append(mRas.size());
        sb.append(" filtered RAs: ");
        sb.append(mNumFilteredRas);
        sb.append(" mDNSs: ");
        sb.append(mOffloadRules.size());
        sb.append(" }");
        return sb.toString();
    }

    private void installPacketFilter(byte[] program, String logInfo) {
        if (!mApfController.installPacketFilter(program, logInfo)) {
            sendNetworkQuirkMetrics(NetworkQuirkEvent.QE_APF_INSTALL_FAILURE);
        }
    }

    private ApfV4GeneratorBase<?> createApfGenerator() throws IllegalInstructionException {
        if (useApfV6Generator()) {
            return new ApfV6Generator(mApfVersionSupported, mApfRamSize,
                    mInstallableProgramSizeClamp);
        } else {
            return new ApfV4Generator(mApfVersionSupported, mApfRamSize,
                    mInstallableProgramSizeClamp);
        }
    }

    /**
     * Generate and install a new filter program.
     */
    @VisibleForTesting
    public void installNewProgram() {
        ArrayList<Ra> rasToFilter = new ArrayList<>();
        final byte[] program;
        int programMinLft = Integer.MAX_VALUE;

        // Ensure the entire APF program uses the same time base.
        final int timeSeconds = secondsSinceBoot();
        // Every return from this function calls installPacketFilter().
        mLastTimeInstalledProgram = timeSeconds;

        // Increase the counter before we generate the program.
        // This keeps the APF_PROGRAM_ID counter in sync with the program.
        mNumProgramUpdates++;

        try {
            // Step 1: Determine how many RA filters we can fit in the program.

            ApfV4GeneratorBase<?> gen = createApfGenerator();
            short labelCheckMdnsQueryPayload = gen.getUniqueLabel();

            emitPrologue(gen, labelCheckMdnsQueryPayload);

            // The epilogue normally goes after the RA filters, but add it early to include its
            // length when estimating the total.
            emitEpilogue(gen);

            if (enableMdns4Offload() || enableMdns6Offload()) {
                generateMdnsQueryOffload((ApfV6GeneratorBase<?>) gen, labelCheckMdnsQueryPayload);
            }

            // Can't fit the program even without any RA filters?
            if (gen.programLengthOverEstimate() > mMaximumApfProgramSize) {
                Log.e(TAG, "Program exceeds maximum size " + mMaximumApfProgramSize);
                sendNetworkQuirkMetrics(NetworkQuirkEvent.QE_APF_OVER_SIZE_FAILURE);
                installPacketFilter(new byte[mMaximumApfProgramSize],
                        getApfConfigMessage() + " (clear memory, reason: program too large)");
                return;
            }

            for (Ra ra : mRas) {
                // skip filter if it has expired.
                if (ra.getRemainingFilterLft(timeSeconds) <= 0) continue;
                ra.generateFilter(gen, timeSeconds);
                // Stop if we get too big.
                if (gen.programLengthOverEstimate() > mMaximumApfProgramSize) {
                    Log.i(TAG, "Past maximum program size, skipping RAs");
                    break;
                }

                rasToFilter.add(ra);
            }

            // Step 2: Actually generate the program
            gen = createApfGenerator();
            labelCheckMdnsQueryPayload = gen.getUniqueLabel();
            emitPrologue(gen, labelCheckMdnsQueryPayload);
            mNumFilteredRas = rasToFilter.size();
            for (Ra ra : rasToFilter) {
                ra.generateFilter(gen, timeSeconds);
                programMinLft = Math.min(programMinLft, ra.getRemainingFilterLft(timeSeconds));
            }
            emitEpilogue(gen);
            if (enableMdns4Offload() || enableMdns6Offload()) {
                generateMdnsQueryOffload((ApfV6GeneratorBase<?>) gen, labelCheckMdnsQueryPayload);
            }
            program = gen.generate();
        } catch (IllegalInstructionException | IllegalStateException | IllegalArgumentException e) {
            Log.wtf(TAG, "Failed to generate APF program.", e);
            sendNetworkQuirkMetrics(NetworkQuirkEvent.QE_APF_GENERATE_FILTER_EXCEPTION);
            installPacketFilter(new byte[mMaximumApfProgramSize],
                    getApfConfigMessage() + String.format(" (clear memory, reason: %s)",
                            e.getMessage()));
            return;
        }
        if (mIsRunning) {
            installPacketFilter(program, getApfConfigMessage());
        }
        mLastInstalledProgramMinLifetime = programMinLft;
        mLastInstalledProgram = program;
        mMaxProgramSize = Math.max(mMaxProgramSize, program.length);

    }

    private void hexDump(String msg, byte[] packet, int length) {
        log(msg + HexDump.toHexString(packet, 0, length, false /* lowercase */));
    }

    // Get the minimum value excludes zero. This is used for calculating the lowest lifetime values
    // in RA packets. Zero lifetimes are excluded because we want to detect whether there is any
    // unusually small lifetimes but zero lifetime is actually valid (cease to be a default router
    // or the option is no longer be used). Number of zero lifetime RAs is collected in a different
    // Metrics.
    private long getMinForPositiveValue(long oldMinValue, long value) {
        if (value < 1) return oldMinValue;
        return Math.min(oldMinValue, value);
    }

    private int getMinForPositiveValue(int oldMinValue, int value) {
        return (int) getMinForPositiveValue((long) oldMinValue, (long) value);
    }

    /**
     * Process an RA packet, updating the list of known RAs and installing a new APF program
     * if the current APF program should be updated.
     */
    @VisibleForTesting
    public void processRa(byte[] packet, int length) {
        final Ra ra;
        try {
            ra = new Ra(packet, length);
        } catch (Exception e) {
            Log.e(TAG, "Error parsing RA", e);
            mNumParseErrorRas++;
            return;
        }

        // Update info for Metrics
        mLowestRouterLifetimeSeconds = getMinForPositiveValue(
                mLowestRouterLifetimeSeconds, ra.routerLifetime());
        mLowestPioValidLifetimeSeconds = getMinForPositiveValue(
                mLowestPioValidLifetimeSeconds, ra.minPioValidLifetime());
        mLowestRioRouteLifetimeSeconds = getMinForPositiveValue(
                mLowestRioRouteLifetimeSeconds, ra.minRioRouteLifetime());
        mLowestRdnssLifetimeSeconds = getMinForPositiveValue(
                mLowestRdnssLifetimeSeconds, ra.minRdnssLifetime());

        // Remove all expired RA filters before trying to match the new RA.
        // TODO: matches() still checks that the old RA filter has not expired. Consider removing
        // that check.
        final int now = secondsSinceBoot();
        mRas.removeIf(item -> item.getRemainingFilterLft(now) <= 0);

        // Have we seen this RA before?
        for (int i = 0; i < mRas.size(); i++) {
            final Ra oldRa = mRas.get(i);
            final Ra.MatchType result = oldRa.matches(ra);
            if (result == Ra.MatchType.MATCH_PASS) {
                log("Updating RA from " + oldRa + " to " + ra);

                // Keep mRas in LRU order so as to prioritize generating filters for recently seen
                // RAs. LRU prioritizes this because RA filters are generated in order from mRas
                // until the filter program exceeds the maximum filter program size allowed by the
                // chipset, so RAs appearing earlier in mRas are more likely to make it into the
                // filter program.
                // TODO: consider sorting the RAs in order of increasing expiry time as well.
                // Swap to front of array.
                mRas.remove(i);
                mRas.add(0, ra);

                // Rate limit program installation
                if (mTokenBucket.get()) {
                    installNewProgram();
                } else {
                    Log.e(TAG, "Failed to install prog for tracked RA, too many updates. " + ra);
                }
                return;
            } else if (result == Ra.MatchType.MATCH_DROP) {
                log("Ignoring RA " + ra + " which matches " + oldRa);
                return;
            }
        }
        mMaxDistinctRas = Math.max(mMaxDistinctRas, mRas.size() + 1);
        if (mRas.size() >= MAX_RAS) {
            // Remove the last (i.e. oldest) RA.
            mRas.remove(mRas.size() - 1);
        }
        log("Adding " + ra);
        mRas.add(0, ra);
        // Rate limit program installation
        if (mTokenBucket.get()) {
            installNewProgram();
        } else {
            Log.e(TAG, "Failed to install prog for new RA, too many updates. " + ra);
        }
    }

    /**
     * Create an {@link ApfFilter} if {@code apfCapabilities} indicates support for packet
     * filtering using APF programs.
     */
    public static ApfFilter maybeCreate(Handler handler, Context context, ApfConfiguration config,
            InterfaceParams ifParams, IApfController apfController,
            NetworkQuirkMetrics networkQuirkMetrics) {
        if (context == null || config == null || ifParams == null) return null;
        if (!ApfV4Generator.supportsVersion(config.apfVersionSupported)) {
            return null;
        }
        if (config.apfRamSize < 512) {
            Log.e(TAG, "Unacceptably small APF limit: " + config.apfRamSize);
            return null;
        }

        return new ApfFilter(handler, context, config, ifParams, apfController,
                networkQuirkMetrics);
    }

    private void collectAndSendMetrics() {
        if (mIpClientRaInfoMetrics == null || mApfSessionInfoMetrics == null) return;
        final long sessionDurationMs = mDependencies.elapsedRealtime() - mSessionStartMs;
        if (sessionDurationMs < mMinMetricsSessionDurationMs) return;

        // Collect and send IpClientRaInfoMetrics.
        mIpClientRaInfoMetrics.setMaxNumberOfDistinctRas(mMaxDistinctRas);
        mIpClientRaInfoMetrics.setNumberOfZeroLifetimeRas(mNumZeroLifetimeRas);
        mIpClientRaInfoMetrics.setNumberOfParsingErrorRas(mNumParseErrorRas);
        mIpClientRaInfoMetrics.setLowestRouterLifetimeSeconds(mLowestRouterLifetimeSeconds);
        mIpClientRaInfoMetrics.setLowestPioValidLifetimeSeconds(mLowestPioValidLifetimeSeconds);
        mIpClientRaInfoMetrics.setLowestRioRouteLifetimeSeconds(mLowestRioRouteLifetimeSeconds);
        mIpClientRaInfoMetrics.setLowestRdnssLifetimeSeconds(mLowestRdnssLifetimeSeconds);
        mIpClientRaInfoMetrics.statsWrite();

        // Collect and send ApfSessionInfoMetrics.
        mApfSessionInfoMetrics.setVersion(mApfVersionSupported);
        mApfSessionInfoMetrics.setMemorySize(mApfRamSize);
        mApfSessionInfoMetrics.setApfSessionDurationSeconds(
                (int) (sessionDurationMs / DateUtils.SECOND_IN_MILLIS));
        mApfSessionInfoMetrics.setNumOfTimesApfProgramUpdated(mNumProgramUpdates);
        mApfSessionInfoMetrics.setMaxProgramSize(mMaxProgramSize);
        for (Map.Entry<Counter, Long> entry : mApfCounterTracker.getCounters().entrySet()) {
            if (entry.getValue() > 0) {
                mApfSessionInfoMetrics.addApfCounter(entry.getKey(), entry.getValue());
            }
        }
        mApfSessionInfoMetrics.statsWrite();
    }

    public void shutdown() {
        collectAndSendMetrics();
        // The shutdown() must be called from the IpClient's handler thread
        mRaPacketReader.stop();
        mRas.clear();
        mDependencies.removeBroadcastReceiver(mDeviceIdleReceiver);
        mIsApfShutdown = true;
        if (SdkLevel.isAtLeastV() && mApfMdnsOffloadEngine != null) {
            mApfMdnsOffloadEngine.unregisterOffloadEngine();
        }

        if (mMulticastReportMonitor != null) {
            mMulticastReportMonitor.stop();
        }
    }

    public void setMulticastFilter(boolean isEnabled) {
        if (mMulticastFilter == isEnabled) return;
        mMulticastFilter = isEnabled;
        installNewProgram();
    }

    @VisibleForTesting
    public void setDozeMode(boolean isEnabled) {
        if (mInDozeMode == isEnabled) return;
        mInDozeMode = isEnabled;
        installNewProgram();
    }

    /** Retrieve the single IPv4 LinkAddress if there is one, otherwise return null. */
    private static LinkAddress retrieveIPv4LinkAddress(LinkProperties lp) {
        LinkAddress ipv4Address = null;
        for (LinkAddress address : lp.getLinkAddresses()) {
            if (!(address.getAddress() instanceof Inet4Address)) {
                continue;
            }
            if (ipv4Address != null && !ipv4Address.isSameAddressAs(address)) {
                // More than one IPv4 address, abort.
                return null;
            }
            ipv4Address = address;
        }
        return ipv4Address;
    }

    /** Retrieve the pair of IPv6 Inet6Address set, otherwise return pair with two empty set.
     *  The first element is a set containing tentative IPv6 addresses,
     *  the second element is a set containing non-tentative IPv6 addresses
     *  */
    private static Pair<Set<Inet6Address>, Set<Inet6Address>>
            retrieveIPv6LinkAddress(LinkProperties lp) {
        final Set<Inet6Address> tentativeAddrs = new ArraySet<>();
        final Set<Inet6Address> nonTentativeAddrs = new ArraySet<>();
        for (LinkAddress address : lp.getLinkAddresses()) {
            if (!(address.getAddress() instanceof Inet6Address)) {
                continue;
            }

            if ((address.getFlags() & IFA_F_TENTATIVE) == IFA_F_TENTATIVE) {
                tentativeAddrs.add((Inet6Address) address.getAddress());
            } else {
                nonTentativeAddrs.add((Inet6Address) address.getAddress());
            }
        }


        return new Pair<>(tentativeAddrs, nonTentativeAddrs);
    }

    public void setLinkProperties(LinkProperties lp) {
        // NOTE: Do not keep a copy of LinkProperties as it would further duplicate state.
        final LinkAddress ipv4Address = retrieveIPv4LinkAddress(lp);
        final byte[] addr = (ipv4Address != null) ? ipv4Address.getAddress().getAddress() : null;
        final int prefix = (ipv4Address != null) ? ipv4Address.getPrefixLength() : 0;
        final Pair<Set<Inet6Address>, Set<Inet6Address>>
                ipv6Addresses = retrieveIPv6LinkAddress(lp);

        if ((prefix == mIPv4PrefixLength)
                && Arrays.equals(addr, mIPv4Address)
                && ipv6Addresses.first.equals(mIPv6TentativeAddresses)
                && ipv6Addresses.second.equals(mIPv6NonTentativeAddresses)
        ) {
            return;
        }
        mIPv4Address = addr;
        mIPv4PrefixLength = prefix;
        mIPv6TentativeAddresses = ipv6Addresses.first;
        mIPv6NonTentativeAddresses = ipv6Addresses.second;
        mIPv6LinkLocalAddress = NetworkStackUtils.selectPreferredIPv6LinkLocalAddress(lp);

        installNewProgram();
    }

    public void updateClatInterfaceState(boolean add) {
        if (mHasClat == add) {
            return;
        }
        mHasClat = add;
        installNewProgram();
    }

    private boolean updateIPv6MulticastAddrs() {
        final Set<Inet6Address> mcastAddrs =
                new ArraySet<>(mDependencies.getIPv6MulticastAddresses(mInterfaceParams.name));

        if (!mIPv6MulticastAddresses.equals(mcastAddrs)) {
            mIPv6MulticastAddresses.clear();
            mIPv6MulticastAddresses.addAll(mcastAddrs);

            mIPv6McastAddrsExcludeAllHost.clear();
            mIPv6McastAddrsExcludeAllHost.addAll(mIPv6MulticastAddresses);
            mIPv6McastAddrsExcludeAllHost.remove(IPV6_ADDR_ALL_NODES_MULTICAST);
            mIPv6McastAddrsExcludeAllHost.remove(IPV6_ADDR_NODE_LOCAL_ALL_NODES_MULTICAST);
            return true;
        }
        return false;
    }

    private boolean updateIPv4MulticastAddrs() {
        final Set<Inet4Address> mcastAddrs =
                new ArraySet<>(mDependencies.getIPv4MulticastAddresses(mInterfaceParams.name));

        if (!mIPv4MulticastAddresses.equals(mcastAddrs)) {
            mIPv4MulticastAddresses.clear();
            mIPv4MulticastAddresses.addAll(mcastAddrs);

            mIPv4McastAddrsExcludeAllHost.clear();
            mIPv4McastAddrsExcludeAllHost.addAll(mcastAddrs);
            mIPv4McastAddrsExcludeAllHost.remove(IPV4_ADDR_ALL_HOST_MULTICAST);
            return true;
        }
        return false;
    }

    /**
     * Updates IPv4/IPv6 multicast addresses.
     */
    public void updateMulticastAddrs() {
        boolean ipv6MulticastUpdated = updateIPv6MulticastAddrs();
        boolean ipv4MulticastUpdated = updateIPv4MulticastAddrs();
        if (ipv6MulticastUpdated || ipv4MulticastUpdated) {
            installNewProgram();
        }
    }

    @ChecksSdkIntAtLeast(api = 35 /* Build.VERSION_CODES.VanillaIceCream */)
    private boolean enableArpOffload() {
        return mHandleArpOffload && useApfV6Generator() && mIPv4Address != null;
    }

    @ChecksSdkIntAtLeast(api = 35 /* Build.VERSION_CODES.VanillaIceCream */)
    public boolean enableNdOffload() {
        return mHandleNdOffload && useApfV6Generator();
    }

    @ChecksSdkIntAtLeast(api = 35 /* Build.VERSION_CODES.VanillaIceCream */)
    private boolean enableOffloadEngineRegistration() {
        return mHandleMdnsOffload && useApfV6Generator();
    }

    @ChecksSdkIntAtLeast(api = 35 /* Build.VERSION_CODES.VanillaIceCream */)
    private boolean enableIgmpReportsMonitor() {
        return mHandleIgmpOffload && useApfV6Generator();
    }

    @ChecksSdkIntAtLeast(api = 35 /* Build.VERSION_CODES.VanillaIceCream */)
    private boolean enableMdns4Offload() {
        return enableOffloadEngineRegistration() && mIPv4Address != null
                && !mOffloadRules.isEmpty();
    }

    @ChecksSdkIntAtLeast(api = 35 /* Build.VERSION_CODES.VanillaIceCream */)
    private boolean enableMdns6Offload() {
        return enableOffloadEngineRegistration() && mIPv6LinkLocalAddress != null
                && !mOffloadRules.isEmpty();
    }

    @ChecksSdkIntAtLeast(api = 35 /* Build.VERSION_CODES.VanillaIceCream */)
    private boolean enableIgmpOffload() {
        // Since the all-hosts multicast address (224.0.0.1) is always present for IPv4
        // multicast, and IGMP packets are not needed for this address, IGMP offloading is only
        // necessary if there are additional joined multicast addresses
        // (mIPv4MulticastAddresses.size() > 1).
        return enableIgmpReportsMonitor() && mIPv4MulticastAddresses.size() > 1
                && mIPv4Address != null;
    }

    @ChecksSdkIntAtLeast(api = 35 /* Build.VERSION_CODES.VanillaIceCream */)
    private boolean enableIpv4PingOffload() {
        return mHandleIpv4PingOffload && useApfV6Generator() && mIPv4Address != null;
    }

    @ChecksSdkIntAtLeast(api = 35 /* Build.VERSION_CODES.VanillaIceCream */)
    private boolean enableIpv6PingOffload() {
        return mHandleIpv6PingOffload && useApfV6Generator()
                && !mIPv6NonTentativeAddresses.isEmpty();
    }

    @ChecksSdkIntAtLeast(api = 35 /* Build.VERSION_CODES.VanillaIceCream */)
    private boolean enableMldReportsMonitor() {
        return mHandleMldOffload && useApfV6Generator();
    }

    @ChecksSdkIntAtLeast(api = 35 /* Build.VERSION_CODES.VanillaIceCream */)
    private boolean enableMldOffload() {
        return enableMldReportsMonitor() && mIPv6LinkLocalAddress != null
                && !mIPv6McastAddrsExcludeAllHost.isEmpty();
    }

    @ChecksSdkIntAtLeast(api = 35 /* Build.VERSION_CODES.VanillaIceCream */)
    private boolean useApfV6Generator() {
        return SdkLevel.isAtLeastV() && ApfV6Generator.supportsVersion(mApfVersionSupported);
    }

    /**
     * Add TCP keepalive ack packet filter.
     * This will add a filter to drop acks to the keepalive packet passed as an argument.
     *
     * @param slot The index used to access the filter.
     * @param sentKeepalivePacket The attributes of the sent keepalive packet.
     */
    public void addTcpKeepalivePacketFilter(final int slot,
            final TcpKeepalivePacketDataParcelable sentKeepalivePacket) {
        log("Adding keepalive ack(" + slot + ")");
        if (null != mKeepalivePackets.get(slot)) {
            throw new IllegalArgumentException("Keepalive slot " + slot + " is occupied");
        }
        final int ipVersion = sentKeepalivePacket.srcAddress.length == 4 ? 4 : 6;
        mKeepalivePackets.put(slot, (ipVersion == 4)
                ? new TcpKeepaliveAckV4(sentKeepalivePacket)
                : new TcpKeepaliveAckV6(sentKeepalivePacket));
        installNewProgram();
    }

    /**
     * Add NAT-T keepalive packet filter.
     * This will add a filter to drop NAT-T keepalive packet which is passed as an argument.
     *
     * @param slot The index used to access the filter.
     * @param sentKeepalivePacket The attributes of the sent keepalive packet.
     */
    public void addNattKeepalivePacketFilter(final int slot,
            final NattKeepalivePacketDataParcelable sentKeepalivePacket) {
        log("Adding NAT-T keepalive packet(" + slot + ")");
        if (null != mKeepalivePackets.get(slot)) {
            throw new IllegalArgumentException("NAT-T Keepalive slot " + slot + " is occupied");
        }

        // TODO : update ApfFilter to support dropping v6 keepalives
        if (sentKeepalivePacket.srcAddress.length != 4) {
            return;
        }

        mKeepalivePackets.put(slot, new NattKeepaliveResponse(sentKeepalivePacket));
        installNewProgram();
    }

    /**
     * Remove keepalive packet filter.
     *
     * @param slot The index used to access the filter.
     */
    public void removeKeepalivePacketFilter(int slot) {
        log("Removing keepalive packet(" + slot + ")");
        mKeepalivePackets.remove(slot);
        installNewProgram();
    }

    /**
     * Determines whether the APF interpreter advertises support for the data buffer access
     * opcodes LDDW (LoaD Data Word) and STDW (STore Data Word).
     */
    public boolean hasDataAccess(int apfVersionSupported) {
        return apfVersionSupported > 2;
    }

    public void dump(IndentingPrintWriter pw) {
        pw.println(String.format(
                "Capabilities: { apfVersionSupported: %d, maximumApfProgramSize: %d }",
                mApfVersionSupported, mApfRamSize));
        pw.println("InstallableProgramSizeClamp: " + mInstallableProgramSizeClamp);
        pw.println("Filter update status: " + (mIsRunning ? "RUNNING" : "PAUSED"));
        pw.println("ApfConfig: " + getApfConfigMessage());
        pw.println("Minimum RDNSS lifetime: " + mMinRdnssLifetimeSec);
        pw.println("Interface MAC address: " + MacAddress.fromBytes(mHardwareAddress));
        pw.println("Multicast MAC addresses: ");
        pw.increaseIndent();
        for (byte[] addr : mDependencies.getEtherMulticastAddresses(mInterfaceParams.name)) {
            pw.println(MacAddress.fromBytes(addr));
        }
        pw.decreaseIndent();
        if (SdkLevel.isAtLeastV()) {
            pw.print("Hardcoded not denylisted Ethertypes:");
            pw.println(" 0800(IPv4) 0806(ARP) 86DD(IPv6) 888E(EAPOL) 88B4(WAPI)");
        } else {
            pw.print("Denylisted Ethertypes:");
            for (int p : mEthTypeBlackList) {
                pw.print(String.format(" %04x", p));
            }
        }
        try {
            pw.println("IPv4 address: " + InetAddress.getByAddress(mIPv4Address).getHostAddress());
        } catch (UnknownHostException | NullPointerException e) {
            pw.println("IPv4 address: None");
        }

        pw.println("IPv4 multicast addresses: ");
        pw.increaseIndent();
        final List<Inet4Address> ipv4McastAddrs =
                ProcfsParsingUtils.getIPv4MulticastAddresses(mInterfaceParams.name);
        for (Inet4Address addr: ipv4McastAddrs) {
            pw.println(addr.getHostAddress());
        }
        pw.decreaseIndent();
        pw.println("IPv6 non-tentative addresses: ");
        pw.increaseIndent();
        for (Inet6Address addr : mIPv6NonTentativeAddresses) {
            pw.println(addr.getHostAddress());
        }
        pw.decreaseIndent();
        pw.println("IPv6 tentative addresses: ");
        pw.increaseIndent();
        for (Inet6Address addr : mIPv6TentativeAddresses) {
            pw.println(addr.getHostAddress());
        }
        pw.decreaseIndent();
        pw.println("IPv6 anycast addresses:");
        pw.increaseIndent();
        final List<Inet6Address> anycastAddrs =
                ProcfsParsingUtils.getAnycast6Addresses(mInterfaceParams.name);
        for (Inet6Address addr : anycastAddrs) {
            pw.println(addr.getHostAddress());
        }
        pw.decreaseIndent();
        pw.println("IPv6 multicast addresses:");
        pw.increaseIndent();
        final List<Inet6Address> multicastAddrs =
                ProcfsParsingUtils.getIpv6MulticastAddresses(mInterfaceParams.name);
        for (Inet6Address addr : multicastAddrs) {
            pw.println(addr.getHostAddress());
        }
        pw.decreaseIndent();

        if (mLastTimeInstalledProgram == 0) {
            pw.println("No program installed.");
            return;
        }
        pw.println("Program updates: " + mNumProgramUpdates);
        int filterAgeSeconds = secondsSinceBoot() - mLastTimeInstalledProgram;
        pw.println(String.format(
                "Last program length %d, installed %ds ago, lifetime %ds",
                mLastInstalledProgram.length, filterAgeSeconds,
                mLastInstalledProgramMinLifetime));
        pw.println();
        pw.println("Mdns filters:");
        pw.increaseIndent();
        for (MdnsOffloadRule rule : mOffloadRules) {
            pw.println(
                    String.format("offloaded service: %s, payloadSize: %d", rule.mFullServiceName,
                            rule.mOffloadPayload == null ? 0 : rule.mOffloadPayload.length));
        }
        pw.decreaseIndent();
        pw.println();
        pw.println("RA filters:");
        pw.increaseIndent();
        for (int i = 0; i < mRas.size(); ++i) {
            if (i < mNumFilteredRas) {
                pw.println("Filtered: ");
            } else {
                pw.println("Ignored: ");
            }
            final Ra ra = mRas.get(i);
            pw.println(ra);
            pw.increaseIndent();
            pw.println(String.format(
                    "Last seen %ds ago", secondsSinceBoot() - ra.mLastSeen));
            pw.println("Last match:");
            pw.increaseIndent();
            pw.println(ra.getLastMatchingPacket());
            pw.decreaseIndent();
            pw.decreaseIndent();
        }
        pw.decreaseIndent();

        pw.println("TCP Keepalive filters:");
        pw.increaseIndent();
        for (int i = 0; i < mKeepalivePackets.size(); ++i) {
            final KeepalivePacket keepalivePacket = mKeepalivePackets.valueAt(i);
            if (keepalivePacket instanceof TcpKeepaliveAck) {
                pw.print("Slot ");
                pw.print(mKeepalivePackets.keyAt(i));
                pw.print(": ");
                pw.println(keepalivePacket);
            }
        }
        pw.decreaseIndent();

        pw.println("NAT-T Keepalive filters:");
        pw.increaseIndent();
        for (int i = 0; i < mKeepalivePackets.size(); ++i) {
            final KeepalivePacket keepalivePacket = mKeepalivePackets.valueAt(i);
            if (keepalivePacket instanceof NattKeepaliveResponse) {
                pw.print("Slot ");
                pw.print(mKeepalivePackets.keyAt(i));
                pw.print(": ");
                pw.println(keepalivePacket);
            }
        }
        pw.decreaseIndent();

        pw.println("Last program:");
        pw.increaseIndent();
        pw.println(HexDump.toHexString(mLastInstalledProgram, false /* lowercase */));
        pw.decreaseIndent();

        pw.println("APF packet counters: ");
        pw.increaseIndent();
        if (!hasDataAccess(mApfVersionSupported)) {
            pw.println("APF counters not supported");
        } else if (mDataSnapshot == null) {
            pw.println("No last snapshot.");
        } else {
            try {
                Counter[] counters = Counter.class.getEnumConstants();
                long counterFilterAgeSeconds =
                        getCounterValue(mDataSnapshot, FILTER_AGE_SECONDS);
                long counterApfProgramId =
                        getCounterValue(mDataSnapshot, APF_PROGRAM_ID);
                for (Counter c : Arrays.asList(counters).subList(1, counters.length)) {
                    long value = getCounterValue(mDataSnapshot, c);

                    String note = "";
                    boolean checkValueIncreases = true;
                    switch (c) {
                        case FILTER_AGE_SECONDS:
                            checkValueIncreases = false;
                            if (value != counterFilterAgeSeconds) {
                                note = " [ERROR: impossible]";
                            } else if (counterApfProgramId < mNumProgramUpdates) {
                                note = " [IGNORE: obsolete program]";
                            } else if (value > filterAgeSeconds) {
                                long offset = value - filterAgeSeconds;
                                note = " [ERROR: in the future by " + offset + "s]";
                            }
                            break;
                        case FILTER_AGE_16384THS:
                            if (mApfVersionSupported > BaseApfGenerator.APF_VERSION_4) {
                                checkValueIncreases = false;
                                if (value % 16384 == 0) {
                                    // valid, but unlikely
                                    note = " [INFO: zero fractional portion]";
                                }
                                if (value / 16384 != counterFilterAgeSeconds) {
                                    // should not be able to happen
                                    note = " [ERROR: mismatch with FILTER_AGE_SECONDS]";
                                }
                            } else if (value != 0) {
                                note = " [UNEXPECTED: APF<=4, yet non-zero]";
                            }
                            break;
                        case APF_PROGRAM_ID:
                            if (value != counterApfProgramId) {
                                note = " [ERROR: impossible]";
                            } else if (value < mNumProgramUpdates) {
                                note = " [WARNING: OBSOLETE PROGRAM]";
                            } else if (value > mNumProgramUpdates) {
                                note = " [ERROR: INVALID FUTURE ID]";
                            }
                            break;
                        default:
                            break;
                    }

                    // Only print non-zero counters (or those with a note)
                    if (value != 0 || !note.equals("")) {
                        pw.println(c.toString() + ": " + value + note);
                    }

                    if (checkValueIncreases) {
                        // If the counter's value decreases, it may have been cleaned up or there
                        // may be a bug.
                        long oldValue = mApfCounterTracker.getCounters().getOrDefault(c, 0L);
                        if (value < oldValue) {
                            Log.e(TAG, String.format(
                                    "Apf Counter: %s unexpectedly decreased. oldValue: %d. "
                                            + "newValue: %d", c.toString(), oldValue, value));
                        }
                    }
                }
            } catch (ArrayIndexOutOfBoundsException e) {
                pw.println("Uh-oh: " + e);
            }
        }
        pw.decreaseIndent();
    }

    /** Return ApfFilter update status for testing purposes. */
    public boolean isRunning() {
        return mIsRunning;
    }

    /** Pause ApfFilter updates for testing purposes. */
    public void pause() {
        mIsRunning = false;
    }

    /** Resume ApfFilter updates for testing purposes. */
    public void resume() {
        maybeCleanUpApfRam();
        // Since the resume() function and cleanup process invalidate previous counter
        // snapshots, the ApfCounterTracker needs to be reset to maintain reliable, incremental
        // counter tracking.
        mApfCounterTracker.clearCounters();
        mIsRunning = true;
    }

    /** Return data snapshot as hex string for testing purposes. */
    public @Nullable String getDataSnapshotHexString() {
        if (mDataSnapshot == null) {
            return null;
        }
        return HexDump.toHexString(mDataSnapshot, 0, mDataSnapshot.length, false /* lowercase */);
    }

    // TODO: move to android.net.NetworkUtils
    @VisibleForTesting
    public static int ipv4BroadcastAddress(byte[] addrBytes, int prefixLength) {
        return bytesToBEInt(addrBytes) | (int) (Integer.toUnsignedLong(-1) >>> prefixLength);
    }

    private static int uint8(byte b) {
        return b & 0xff;
    }

    private static int getUint16(ByteBuffer buffer, int position) {
        return buffer.getShort(position) & 0xffff;
    }

    private static long getUint32(ByteBuffer buffer, int position) {
        return Integer.toUnsignedLong(buffer.getInt(position));
    }

    private static int getUint8(ByteBuffer buffer, int position) {
        return uint8(buffer.get(position));
    }

    private static int bytesToBEInt(byte[] bytes) {
        return (uint8(bytes[0]) << 24)
                + (uint8(bytes[1]) << 16)
                + (uint8(bytes[2]) << 8)
                + (uint8(bytes[3]));
    }

    private void sendNetworkQuirkMetrics(final NetworkQuirkEvent event) {
        if (mNetworkQuirkMetrics == null) return;
        mNetworkQuirkMetrics.setEvent(event);
        mNetworkQuirkMetrics.statsWrite();
    }
}

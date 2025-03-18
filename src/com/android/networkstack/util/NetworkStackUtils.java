/*
 * Copyright (C) 2019 The Android Open Source Project
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

package com.android.networkstack.util;

import static android.net.apf.ApfConstants.IPV6_SOLICITED_NODES_PREFIX;
import static android.os.Build.VERSION.CODENAME;
import static android.os.Build.VERSION.SDK_INT;
import static android.system.OsConstants.IFA_F_DEPRECATED;
import static android.system.OsConstants.IFA_F_TENTATIVE;

import android.content.Context;
import android.net.IpPrefix;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.MacAddress;
import android.system.ErrnoException;
import android.util.Log;

import androidx.annotation.ChecksSdkIntAtLeast;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.android.net.module.util.DeviceConfigUtils;
import com.android.net.module.util.HexDump;

import java.io.FileDescriptor;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Collection of utilities for the network stack.
 */
public class NetworkStackUtils {
    private static final String TAG = "NetworkStackUtils";

    /**
     * A list of captive portal detection specifications used in addition to the fallback URLs.
     * Each spec has the format url@@/@@statusCodeRegex@@/@@contentRegex. Specs are separated
     * by "@@,@@".
     */
    public static final String CAPTIVE_PORTAL_FALLBACK_PROBE_SPECS =
            "captive_portal_fallback_probe_specs";

    /**
     * A comma separated list of URLs used for captive portal detection in addition to the
     * fallback HTTP url associated with the CAPTIVE_PORTAL_FALLBACK_URL settings.
     */
    public static final String CAPTIVE_PORTAL_OTHER_FALLBACK_URLS =
            "captive_portal_other_fallback_urls";

    /**
     * A comma separated list of URLs used for captive portal detection in addition to the HTTP url
     * associated with the CAPTIVE_PORTAL_HTTP_URL settings.
     */
    public static final String CAPTIVE_PORTAL_OTHER_HTTP_URLS = "captive_portal_other_http_urls";

    /**
     * A comma separated list of URLs used for network validation in addition to the HTTPS url
     * associated with the CAPTIVE_PORTAL_HTTPS_URL settings.
     */
    public static final String CAPTIVE_PORTAL_OTHER_HTTPS_URLS = "captive_portal_other_https_urls";

    /**
     * Which User-Agent string to use in the header of the captive portal detection probes.
     * The User-Agent field is unset when this setting has no value (HttpUrlConnection default).
     */
    public static final String CAPTIVE_PORTAL_USER_AGENT = "captive_portal_user_agent";

    /**
     * Whether to use HTTPS for network validation. This is enabled by default and the setting
     * needs to be set to 0 to disable it. This setting is a misnomer because captive portals
     * don't actually use HTTPS, but it's consistent with the other settings.
     */
    public static final String CAPTIVE_PORTAL_USE_HTTPS = "captive_portal_use_https";

    /**
     * The URL used for HTTPS captive portal detection upon a new connection.
     * A 204 response code from the server is used for validation.
     */
    public static final String CAPTIVE_PORTAL_HTTPS_URL = "captive_portal_https_url";

    /**
     * The URL used for HTTP captive portal detection upon a new connection.
     * A 204 response code from the server is used for validation.
     */
    public static final String CAPTIVE_PORTAL_HTTP_URL = "captive_portal_http_url";

    /**
     * The URL used for fallback HTTP captive portal detection when previous HTTP
     * and HTTPS captive portal detection attemps did not return a conclusive answer.
     */
    public static final String CAPTIVE_PORTAL_FALLBACK_URL = "captive_portal_fallback_url";

    /**
     * What to do when connecting a network that presents a captive portal.
     * Must be one of the CAPTIVE_PORTAL_MODE_* constants above.
     *
     * The default for this setting is CAPTIVE_PORTAL_MODE_PROMPT.
     */
    public static final String CAPTIVE_PORTAL_MODE = "captive_portal_mode";

    /**
     * Don't attempt to detect captive portals.
     */
    public static final int CAPTIVE_PORTAL_MODE_IGNORE = 0;

    /**
     * When detecting a captive portal, display a notification that
     * prompts the user to sign in.
     */
    public static final int CAPTIVE_PORTAL_MODE_PROMPT = 1;

    /**
     * When detecting a captive portal, immediately disconnect from the
     * network and do not reconnect to that network in the future.
     */
    public static final int CAPTIVE_PORTAL_MODE_AVOID = 2;

    /**
     * DNS probe timeout for network validation. Enough for 3 DNS queries 5 seconds apart.
     */
    public static final int DEFAULT_CAPTIVE_PORTAL_DNS_PROBE_TIMEOUT = 12500;

    /**
     * List of fallback probe specs to use for detecting captive portals. This is an alternative to
     * fallback URLs that provides more flexibility on detection rules. Empty, so unused by default.
     */
    public static final String[] DEFAULT_CAPTIVE_PORTAL_FALLBACK_PROBE_SPECS =
            new String[] {};

    /**
     * The default list of HTTP URLs to use for detecting captive portals.
     */
    public static final String[] DEFAULT_CAPTIVE_PORTAL_HTTP_URLS =
            new String [] {"http://connectivitycheck.gstatic.com/generate_204"};

    /**
     * The default list of HTTPS URLs for network validation, to use for confirming internet
     * connectivity.
     */
    public static final String[] DEFAULT_CAPTIVE_PORTAL_HTTPS_URLS =
            new String [] {"https://www.google.com/generate_204"};

    /**
     * Minimum module version at which to enable the DHCP Rapid Commit option.
     */
    public static final String DHCP_RAPID_COMMIT_VERSION = "dhcp_rapid_commit_version";

    /**
     * Minimum module version at which to enable the IP address conflict detection feature.
     */
    public static final String DHCP_IP_CONFLICT_DETECT_VERSION = "dhcp_ip_conflict_detect_version";

    /**
     * Minimum module version at which to enable slow DHCP retransmission approach in renew/rebind
     * state suggested in RFC2131 section 4.4.5.
     */
    public static final String DHCP_SLOW_RETRANSMISSION_VERSION =
            "dhcp_slow_retransmission_version";

    /**
     * Experiment flag to enable considering DNS probes returning private IP addresses as failed
     * when attempting to detect captive portals.
     *
     * This flag is enabled if !=0 and less than the module APK version.
     */
    public static final String DNS_PROBE_PRIVATE_IP_NO_INTERNET_VERSION =
            "dns_probe_private_ip_no_internet";

    /**
     * Experiment flag to enable validation metrics sent by NetworkMonitor.
     *
     * Metrics are sent by default. They can be disabled by setting the flag to a number greater
     * than the APK version (for example 999999999).
     * @see DeviceConfigUtils#isFeatureEnabled(Context, String, String, boolean)
     */
    public static final String VALIDATION_METRICS_VERSION = "validation_metrics_version";

    /**
     * Experiment flag to enable "mcast_resolicit" neighbor parameter in IpReachabilityMonitor,
     * set it to 3 by default.
     */
    public static final String IP_REACHABILITY_MCAST_RESOLICIT_VERSION =
            "ip_reachability_mcast_resolicit_version";

    /**
     * Experiment flag to treat router MAC address changes as a failure only on roam.
     */
    public static final String IP_REACHABILITY_ROUTER_MAC_CHANGE_FAILURE_ONLY_AFTER_ROAM_VERSION =
            "ip_reachability_router_mac_change_failure_only_after_roam_version";

    /**
     * Experiment flag to ignore all NUD failures from kernel organic.
     */
    public static final String IP_REACHABILITY_IGNORE_ORGANIC_NUD_FAILURE_VERSION =
            "ip_reachability_ignore_organic_nud_failure_version";

    /**
     * Experiment flag to enable the feature of polling counters in Apf.
     */
    public static final String APF_POLLING_COUNTERS_VERSION = "apf_polling_counters_version";

    /**
     * Experiment flag to enable the feature of ignoring any individual RA section with lifetime
     * below accept_ra_min_lft sysctl.
     */
    public static final String IPCLIENT_IGNORE_LOW_RA_LIFETIME_VERSION =
            "ipclient_ignore_low_ra_lifetime_version";

    /**
     * Feature flag to send private DNS resolution queries and probes on a background thread.
     */
    public static final String NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION =
            "networkmonitor_async_privdns_resolution";

    /**
     * Experiment flag to populate the IP link address lifetime such as deprecationTime and
     * expirationtTime.
     */
    public static final String IPCLIENT_POPULATE_LINK_ADDRESS_LIFETIME_VERSION =
            "ipclient_populate_link_address_lifetime_version";

    /**
     * Experiment flag to support parsing PIO P flag(DHCPv6-PD preferred).
     */
    public static final String IPCLIENT_DHCPV6_PD_PREFERRED_FLAG_VERSION =
            "ipclient_dhcpv6_pd_preferred_flag_version";

    /**
     * Experiment flag to replace INetd usage with netlink in IpClient.
     */
    public static final String IPCLIENT_REPLACE_NETD_WITH_NETLINK_VERSION =
            "ipclient_replace_netd_with_netlink_version";

    /**
     * Experiment flag to enable Discovery of Designated Resolvers (DDR).
     * This flag requires networkmonitor_async_privdns_resolution flag.
     */
    public static final String DNS_DDR_VERSION = "dns_ddr_version";

    /**
     * Experiment flag to ignore all NUD failures if we've seen too many NUD failure in a network.
     */
    public static final String IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION =
            "ip_reachability_ignore_nud_failure_version";

    /**
     * Experiment flag to enable the feature of handle IPv4 ping offload in Apf.
     */
    public static final String APF_HANDLE_PING4_OFFLOAD_VERSION =
            "apf_handle_ping_offload_version";

    /**
     * Experiment flag to enable the feature of handle IPv6 ping offload in Apf.
     */
    public static final String APF_HANDLE_PING6_OFFLOAD_VERSION =
            "apf_handle_ping6_offload_version";

    /**
     * Experiment flag to enable the feature of handle IGMP offload in Apf.
     */
    public static final String APF_HANDLE_IGMP_OFFLOAD_VERSION =
            "apf_handle_igmp_offload_version";

    /**
     * Experiment flag to enable the feature of handle MLD offload in Apf.
     */
    public static final String APF_HANDLE_MLD_OFFLOAD_VERSION =
            "apf_handle_mld_offload_version";

    /**** BEGIN Feature Kill Switch Flags ****/

    /**
     * Kill switch flag to disable the feature of skipping Tcp socket info polling when light
     * doze mode is enabled.
     */
    public static final String SKIP_TCP_POLL_IN_LIGHT_DOZE = "skip_tcp_poll_in_light_doze_mode";

    /**
     * Experiment flag to enable the feature of re-evaluate when network resumes.
     */
    public static final String REEVALUATE_WHEN_RESUME = "reevaluate_when_resume";

    /**
     * Kill switch flag to disable the feature of ignoring Tcp socket info for uids which
     * networking are blocked.
     */
    public static final String IGNORE_TCP_INFO_FOR_BLOCKED_UIDS =
            "ignore_tcp_info_for_blocked_uids";

    /** Kill switch to force disable APF */
    public static final String APF_ENABLE = "apf_enable";

    /**
     * Kill switch flag to disable the feature of handle arp offload in Apf.
     * Warning: the following flag String is incorrect. The feature that is not chickened out is
     * "ARP offload" not "ARP offload force disabled".
     */
    public static final String APF_HANDLE_ARP_OFFLOAD = "apf_handle_arp_offload_force_disable";

    /**
     * Kill switch flag to disable the feature of handle nd offload in Apf.
     */
    public static final String APF_HANDLE_ND_OFFLOAD = "apf_handle_nd_offload";

    /**
     * Kill switch flag to disable the feature of handle IGMP offload in Apf.
     */
    public static final String APF_HANDLE_IGMP_OFFLOAD = "apf_handle_igmp_offload";

    /**
     * Kill switch flag to disable the feature of handle MLD offload in Apf.
     */
    public static final String APF_HANDLE_MLD_OFFLOAD = "apf_handle_mld_offload";

    /**
     * Kill switch flag to disable the feature of handle IPv4 ping offload in Apf.
     */
    public static final String APF_HANDLE_PING4_OFFLOAD = "apf_handle_ping4_offload";

    /**
     * Kill switch flag to disable the feature of handle IPv6 ping offload in Apf.
     */
    public static final String APF_HANDLE_PING6_OFFLOAD = "apf_handle_ping6_offload";
    static {
        System.loadLibrary("networkstackutilsjni");
    }

    /**
     * Convert IPv4 multicast address to ethernet multicast address in network order.
     */
    public static MacAddress ipv4MulticastToEthernetMulticast(@NonNull final Inet4Address addr) {
        final byte[] etherMulticast = new byte[6];
        final byte[] ipv4Multicast = addr.getAddress();
        etherMulticast[0] = (byte) 0x01;
        etherMulticast[1] = (byte) 0x00;
        etherMulticast[2] = (byte) 0x5e;
        etherMulticast[3] = (byte) (ipv4Multicast[1] & 0x7f);
        etherMulticast[4] = ipv4Multicast[2];
        etherMulticast[5] = ipv4Multicast[3];
        return MacAddress.fromBytes(etherMulticast);
    }

    /**
     * Convert IPv6 multicast address to ethernet multicast address in network order.
     */
    public static MacAddress ipv6MulticastToEthernetMulticast(@NonNull final Inet6Address addr) {
        final byte[] etherMulticast = new byte[6];
        final byte[] ipv6Multicast = addr.getAddress();
        etherMulticast[0] = (byte) 0x33;
        etherMulticast[1] = (byte) 0x33;
        etherMulticast[2] = ipv6Multicast[12];
        etherMulticast[3] = ipv6Multicast[13];
        etherMulticast[4] = ipv6Multicast[14];
        etherMulticast[5] = ipv6Multicast[15];
        return MacAddress.fromBytes(etherMulticast);
    }

    /**
     * Convert IPv6 unicast or anycast address to solicited node multicast address
     * per RFC4291 section 2.7.1.
     */
    @Nullable
    public static Inet6Address ipv6AddressToSolicitedNodeMulticast(
            @NonNull final Inet6Address addr) {
        final byte[] address = new byte[16];
        address[0] = (byte) 0xFF;
        address[1] = (byte) 0x02;
        address[11] = (byte) 0x01;
        address[12] = (byte) 0xFF;
        address[13] = addr.getAddress()[13];
        address[14] = addr.getAddress()[14];
        address[15] = addr.getAddress()[15];
        try {
            return (Inet6Address) InetAddress.getByAddress(address);
        } catch (UnknownHostException e) {
            Log.e(TAG, "Invalid host IP address " + addr.getHostAddress(), e);
            return null;
        }
    }

    /**
     * Checks if the given IPv6 address is a solicited-node multicast address.
     *
     * <p>Solicited-node multicast addresses are used for Neighbor Discovery in IPv6.
     * They have a specific prefix (FF02::1:FFxx:xxxx) where the last 64 bits are derived
     * from the interface's link-layer address. This function only checks if the address
     * has the correct prefix; it does *not* verify the lower 64 bits.
     */
    public static boolean isIPv6AddressSolicitedNodeMulticast(@NonNull final Inet6Address addr) {
        for (int i = 0; i < IPV6_SOLICITED_NODES_PREFIX.length; i++) {
            if (addr.getAddress()[i] != IPV6_SOLICITED_NODES_PREFIX[i]) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check whether a link address is IPv6 global preferred unicast address.
     */
    public static boolean isIPv6GUA(@NonNull final LinkAddress address) {
        return address.isIpv6() && address.isGlobalPreferred();
    }

    /**
     * Convert 48bits MAC address to 64bits link-layer address(EUI64).
     *     1. insert the 0xFFFE in the middle of mac address
     *     2. flip the 7th bit(universal/local) of the first byte.
     */
    public static byte[] macAddressToEui64(@NonNull final MacAddress hwAddr) {
        final byte[] eui64 = new byte[8];
        final byte[] mac48 = hwAddr.toByteArray();
        System.arraycopy(mac48 /* src */, 0 /* srcPos */, eui64 /* dest */, 0 /* destPos */,
                3 /* length */);
        eui64[3] = (byte) 0xFF;
        eui64[4] = (byte) 0xFE;
        System.arraycopy(mac48 /* src */, 3 /* srcPos */, eui64 /* dest */, 5 /* destPos */,
                3 /* length */);
        eui64[0] = (byte) (eui64[0] ^ 0x02); // flip 7th bit
        return eui64;
    }

    /**
     * Generate an IPv6 address based on the given prefix(/64) and stable interface
     * identifier(EUI64).
     */
    @Nullable
    public static Inet6Address createInet6AddressFromEui64(@NonNull final IpPrefix prefix,
            @NonNull final byte[] eui64) {
        if (prefix.getPrefixLength() > 64) {
            Log.e(TAG, "Invalid IPv6 prefix length " + prefix.getPrefixLength());
            return null;
        }
        final byte[] address = new byte[16];
        System.arraycopy(prefix.getRawAddress() /* src */, 0 /* srcPos */, address /* dest */,
                0 /* destPos*/, 8 /* length */);
        System.arraycopy(eui64 /* src */, 0 /* srcPos */, address /* dest */, 8 /* destPos */,
                eui64.length);
        try {
            return (Inet6Address) InetAddress.getByAddress(address);
        } catch (UnknownHostException e) {
            Log.e(TAG, "Invalid IPv6 address " + HexDump.toHexString(address), e);
            return null;
        }
    }

    /** Checks if the device is running on a release version of Android Baklava or newer */
    @ChecksSdkIntAtLeast(api = 36 /* BUILD_VERSION_CODES.Baklava */)
    public static boolean isAtLeast25Q2() {
        return SDK_INT >= 36 || (SDK_INT == 35 && isAtLeastPreReleaseCodename("Baklava"));
    }

    private static boolean isAtLeastPreReleaseCodename(@NonNull String codename) {
        // Special case "REL", which means the build is not a pre-release build.
        if ("REL".equals(CODENAME)) {
            return false;
        }

        // Otherwise lexically compare them. Return true if the build codename is equal to or
        // greater than the requested codename.
        return CODENAME.compareTo(codename) >= 0;
    }

    /**
     * Select the preferred IPv6 link-local address based on the rules defined in rfc3484,
     * Section 5.
     * <p>
     * The address selection criteria are as follows:
     * 1. Select a non-tentative, non-deprecated address, if available.
     * 2. If no such address exists, select any non-tentative address.
     */
    public static Inet6Address selectPreferredIPv6LinkLocalAddress(@NonNull LinkProperties lp) {
        Inet6Address preferredAddress = null;
        for (LinkAddress linkAddress : lp.getLinkAddresses()) {
            final InetAddress inetAddress = linkAddress.getAddress();
            final int flags = linkAddress.getFlags();

            if (!(inetAddress instanceof Inet6Address)) {
                continue;
            }

            if (!inetAddress.isLinkLocalAddress()) {
                continue;
            }

            if ((flags & IFA_F_TENTATIVE) != 0) {
                continue;
            }

            preferredAddress = (Inet6Address) inetAddress;
            if ((flags & IFA_F_DEPRECATED) == 0L) {
                return preferredAddress;
            }
        }

        return preferredAddress;
    }

    /**
     * Attaches a socket filter that accepts DHCP packets to the given socket.
     */
    public static native void attachDhcpFilter(FileDescriptor fd) throws ErrnoException;

    /**
     * Attaches a socket filter that accepts ICMPv6 router advertisements to the given socket.
     * @param fd the socket's {@link FileDescriptor}.
     */
    public static native void attachRaFilter(FileDescriptor fd) throws ErrnoException;

    /**
     * Attaches a socket filter that accepts L2-L4 signaling traffic required for IP connectivity.
     *
     * This includes: all ARP, ICMPv6 RS/RA/NS/NA messages, and DHCPv4 exchanges.
     *
     * @param fd the socket's {@link FileDescriptor}.
     */
    public static native void attachControlPacketFilter(FileDescriptor fd) throws ErrnoException;

    /**
     * Add an entry into the ARP cache.
     */
    public static void addArpEntry(Inet4Address ipv4Addr, android.net.MacAddress ethAddr,
            String ifname, FileDescriptor fd) throws IOException {
        addArpEntry(ethAddr.toByteArray(), ipv4Addr.getAddress(), ifname, fd);
    }

    /**
     * Attaches a socket filter that accepts egress IGMPv2/IGMPv3 reports to the given socket.
     *
     * This filter doesn't include IGMPv1 report since device will not send out IGMPv1 report
     * when the device leaves a multicast address group.
     *
     * @param fd the socket's {@link FileDescriptor}.
     */
    public static native void attachEgressIgmpReportFilter(FileDescriptor fd) throws ErrnoException;

    /**
     * Attaches a socket filter that accepts egress IGMPv2/v3, MLDv1/v2 reports to the given socket.
     *
     * This filter doesn't include IGMPv1 report since device will not send out IGMPv1 report
     * when the device leaves a multicast address group.
     *
     * @param fd the socket's {@link FileDescriptor}.
     */
    public static native void attachEgressMulticastReportFilter(
            FileDescriptor fd) throws ErrnoException;

    private static native void addArpEntry(byte[] ethAddr, byte[] netAddr, String ifname,
            FileDescriptor fd) throws IOException;

}

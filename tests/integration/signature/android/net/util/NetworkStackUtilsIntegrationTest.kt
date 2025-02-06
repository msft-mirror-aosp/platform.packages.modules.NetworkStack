/*
 * Copyright (C) 2020 The Android Open Source Project
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

package android.net.util

import android.Manifest.permission.MANAGE_TEST_NETWORKS
import android.content.Context
import android.net.InetAddresses.parseNumericAddress
import android.net.IpPrefix
import android.net.LinkAddress
import android.net.LinkProperties
import android.net.MacAddress
import android.net.TestNetworkInterface
import android.net.TestNetworkManager
import android.net.dhcp.DhcpPacket
import android.os.HandlerThread
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.OsConstants.AF_INET
import android.system.OsConstants.AF_PACKET
import android.system.OsConstants.ETH_P_ALL
import android.system.OsConstants.ETH_P_IPV6
import android.system.OsConstants.IFA_F_DEPRECATED
import android.system.OsConstants.IFA_F_TENTATIVE
import android.system.OsConstants.IPPROTO_UDP
import android.system.OsConstants.RT_SCOPE_LINK
import android.system.OsConstants.SOCK_CLOEXEC
import android.system.OsConstants.SOCK_DGRAM
import android.system.OsConstants.SOCK_NONBLOCK
import android.system.OsConstants.SOCK_RAW
import android.system.OsConstants.SOL_SOCKET
import android.system.OsConstants.SO_RCVTIMEO
import android.system.StructTimeval
import androidx.test.platform.app.InstrumentationRegistry
import com.android.internal.util.HexDump
import com.android.net.module.util.InterfaceParams
import com.android.net.module.util.IpUtils
import com.android.net.module.util.Ipv6Utils
import com.android.net.module.util.NetworkStackConstants.ETHER_ADDR_LEN
import com.android.net.module.util.NetworkStackConstants.ETHER_HEADER_LEN
import com.android.net.module.util.NetworkStackConstants.ETHER_SRC_ADDR_OFFSET
import com.android.net.module.util.NetworkStackConstants.IPV4_ADDR_ANY
import com.android.net.module.util.NetworkStackConstants.IPV4_CHECKSUM_OFFSET
import com.android.net.module.util.NetworkStackConstants.IPV4_FLAGS_OFFSET
import com.android.net.module.util.NetworkStackConstants.IPV4_FLAG_DF
import com.android.net.module.util.NetworkStackConstants.IPV4_FLAG_MF
import com.android.net.module.util.NetworkStackConstants.IPV4_HEADER_MIN_LEN
import com.android.net.module.util.NetworkStackConstants.IPV6_ADDR_ALL_NODES_MULTICAST
import com.android.net.module.util.NetworkStackConstants.UDP_HEADER_LEN
import com.android.net.module.util.structs.PrefixInformationOption
import com.android.networkstack.util.NetworkStackUtils
import com.android.testutils.ArpRequestFilter
import com.android.testutils.IPv4UdpFilter
import com.android.testutils.PollPacketReader
import java.io.FileDescriptor
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.net.NetworkInterface
import java.nio.ByteBuffer
import java.util.Arrays
import kotlin.reflect.KClass
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Before
import org.junit.Test

class NetworkStackUtilsIntegrationTest {
    private val inst by lazy { InstrumentationRegistry.getInstrumentation() }
    private val context by lazy { inst.context }

    private val TEST_TIMEOUT_MS = 10_000L
    private val TEST_MTU = 1500
    private val TEST_TARGET_IPV4_ADDR = parseNumericAddress("192.0.2.42") as Inet4Address
    private val TEST_SRC_MAC = MacAddress.fromString("BA:98:76:54:32:10")
    private val TEST_TARGET_MAC = MacAddress.fromString("01:23:45:67:89:0A")
    private val TEST_INET6ADDR_1 = parseNumericAddress("2001:db8::1") as Inet6Address
    private val TEST_INET6ADDR_2 = parseNumericAddress("2001:db8::2") as Inet6Address
    private val TEST_INET6ADDR_3 = parseNumericAddress("fd01:db8::3") as Inet6Address

    // RFC4291 section 2.7.1
    private val SOLICITED_NODE_MULTICAST_PREFIX = "FF02:0:0:0:0:1:FF00::/104"

    private val readerHandler = HandlerThread(
            NetworkStackUtilsIntegrationTest::class.java.simpleName
    )
    private lateinit var iface: TestNetworkInterface
    private lateinit var reader: PollPacketReader

    @Before
    fun setUp() {
        inst.uiAutomation.adoptShellPermissionIdentity(MANAGE_TEST_NETWORKS)
        try {
            val tnm = context.assertHasService(TestNetworkManager::class)
            iface = tnm.createTapInterface()
        } finally {
            inst.uiAutomation.dropShellPermissionIdentity()
        }
        readerHandler.start()
        reader = PollPacketReader(readerHandler.threadHandler, iface.fileDescriptor.fileDescriptor,
                1500 /* maxPacketSize */)
        readerHandler.threadHandler.post { reader.start() }
    }

    @After
    fun tearDown() {
        readerHandler.quitSafely()
        if (this::iface.isInitialized) iface.fileDescriptor.close()
    }

    @Test
    fun testAddArpEntry() {
        val socket = Os.socket(AF_INET, SOCK_DGRAM or SOCK_NONBLOCK, IPPROTO_UDP)
        SocketUtils.bindSocketToInterface(socket, iface.interfaceName)

        NetworkStackUtils.addArpEntry(
            TEST_TARGET_IPV4_ADDR,
            TEST_TARGET_MAC,
            iface.interfaceName,
            socket
        )

        // Fake DHCP packet: would not be usable as a DHCP offer (most IPv4 addresses are all-zero,
        // no gateway or DNS servers, etc).
        // Using a DHCP packet to replicate actual usage of the API: it is used in DhcpServer to
        // send packets to clients before their IP address has been assigned.
        val buffer = DhcpPacket.buildOfferPacket(DhcpPacket.ENCAP_BOOTP, 123 /* transactionId */,
                false /* broadcast */, IPV4_ADDR_ANY /* serverIpAddr */,
                IPV4_ADDR_ANY /* relayIp */, IPV4_ADDR_ANY /* yourIp */,
                TEST_TARGET_MAC.toByteArray(), 3600 /* timeout */, IPV4_ADDR_ANY /* netMask */,
                IPV4_ADDR_ANY /* bcAddr */, emptyList<Inet4Address>() /* gateways */,
                emptyList<Inet4Address>() /* dnsServers */,
                IPV4_ADDR_ANY /* dhcpServerIdentifier */, null /* domainName */,
                null /* hostname */, false /* metered */, 1500 /* mtu */,
                null /* captivePortalUrl */)
        // Not using .array as per errorprone "ByteBufferBackingArray" recommendation
        val originalPacket = buffer.readAsArray()

        Os.sendto(
            socket,
            originalPacket,
            0 /* bytesOffset */,
            originalPacket.size /* bytesCount */,
            0 /* flags */,
            TEST_TARGET_IPV4_ADDR,
            DhcpPacket.DHCP_CLIENT.toInt() /* port */
        )

        // Verify the packet was sent to the mac address specified in the ARP entry
        // Also accept ARP requests, but expect that none is sent before the UDP packet
        // IPv6 NS may be sent on the interface but will be filtered out
        val sentPacket = reader.poll(TEST_TIMEOUT_MS, IPv4UdpFilter().or(ArpRequestFilter()))
                ?: fail("Packet was not sent on the interface")

        val sentTargetAddr = MacAddress.fromBytes(sentPacket.copyOfRange(0, ETHER_ADDR_LEN))
        assertEquals(TEST_TARGET_MAC, sentTargetAddr, "Destination ethernet address does not match")

        val sentDhcpPacket = sentPacket.copyOfRange(
            ETHER_HEADER_LEN + IPV4_HEADER_MIN_LEN + UDP_HEADER_LEN,
            sentPacket.size
        )

        assertArrayEquals("Sent packet != original packet", originalPacket, sentDhcpPacket)
    }

    private fun doTestAttachRaFilter(generic: Boolean) {
        val socket = Os.socket(AF_PACKET, SOCK_RAW or SOCK_CLOEXEC, 0)
        val ifParams = InterfaceParams.getByName(iface.interfaceName)
                ?: fail("Could not obtain interface params for ${iface.interfaceName}")
        val socketAddr = SocketUtils.makePacketSocketAddress(ETH_P_IPV6, ifParams.index)
        Os.bind(socket, socketAddr)
        Os.setsockoptTimeval(
            socket,
            SOL_SOCKET,
            SO_RCVTIMEO,
            StructTimeval.fromMillis(TEST_TIMEOUT_MS)
        )

        // Verify that before setting any filter, the socket receives pings
        val echo = Ipv6Utils.buildEchoRequestPacket(
            TEST_SRC_MAC,
            TEST_TARGET_MAC,
            TEST_INET6ADDR_1,
            TEST_INET6ADDR_2
        )
        reader.sendResponse(echo)
        echo.rewind()
        assertNextPacketEquals(socket, echo.readAsArray(), "ICMPv6 echo")

        if (generic) {
            NetworkStackUtils.attachControlPacketFilter(socket)
        } else {
            NetworkStackUtils.attachRaFilter(socket)
        }
        // Send another echo, then an RA. After setting the filter expect only the RA.
        echo.rewind()
        reader.sendResponse(echo)
        val pio = PrefixInformationOption.build(
            IpPrefix("2001:db8:1::/64"),
            0.toByte() /* flags */,
            3600 /* validLifetime */,
            1800 /* preferredLifetime */
        )
        val ra = Ipv6Utils.buildRaPacket(TEST_SRC_MAC, TEST_TARGET_MAC,
                TEST_INET6ADDR_1 /* routerAddr */, IPV6_ADDR_ALL_NODES_MULTICAST,
                0.toByte() /* flags */, 1800 /* lifetime */, 0 /* reachableTime */,
                0 /* retransTimer */, pio)
        reader.sendResponse(ra)
        ra.rewind()

        assertNextPacketEquals(socket, ra.readAsArray(), "ICMPv6 RA")
    }

    @Test
    fun testAttachRaFilter() {
        doTestAttachRaFilter(false)
    }

    @Test
    fun testRaViaAttachControlPacketFilter() {
        doTestAttachRaFilter(true)
    }

    @Test
    fun testAttachEgressIgmpReportFilter() {
        val socket = Os.socket(AF_PACKET, SOCK_RAW or SOCK_CLOEXEC, 0)
        val ifParams = InterfaceParams.getByName(iface.interfaceName)
            ?: fail("Could not obtain interface params for ${iface.interfaceName}")
        val socketAddr = SocketUtils.makePacketSocketAddress(ETH_P_ALL, ifParams.index)
        NetworkStackUtils.attachEgressIgmpReportFilter(socket)
        Os.bind(socket, socketAddr)
        Os.setsockoptTimeval(
            socket,
            SOL_SOCKET,
            SO_RCVTIMEO,
            StructTimeval.fromMillis(TEST_TIMEOUT_MS)
        )

        val sendSocket = Os.socket(AF_PACKET, SOCK_RAW or SOCK_CLOEXEC, 0)
        Os.bind(sendSocket, socketAddr)

        testExpectedPacketsReceived(sendSocket, socket)

        // shorten the socket timeout to prevent waiting too long in the test
        Os.setsockoptTimeval(socket, SOL_SOCKET, SO_RCVTIMEO, StructTimeval.fromMillis(100))

        testExpectedPacketsNotReceived(sendSocket, socket)
    }

    @Test
    fun testAttachEgressIgmpReportFilterForMulticastGroupChange() {
        val socket = Os.socket(AF_PACKET, SOCK_RAW or SOCK_CLOEXEC, 0)
        val ifParams = InterfaceParams.getByName(iface.interfaceName)
            ?: fail("Could not obtain interface params for ${iface.interfaceName}")
        val socketAddr = SocketUtils.makePacketSocketAddress(ETH_P_ALL, ifParams.index)
        NetworkStackUtils.attachEgressIgmpReportFilter(socket)
        Os.bind(socket, socketAddr)
        Os.setsockoptTimeval(
            socket,
            SOL_SOCKET,
            SO_RCVTIMEO,
            StructTimeval.fromMillis(TEST_TIMEOUT_MS)
        )

        val multicastSock = MulticastSocket()
        val mcastAddr = InetSocketAddress(InetAddress.getByName("239.0.0.1") as Inet4Address, 5000)
        val networkInterface = NetworkInterface.getByName(iface.interfaceName)

        multicastSock.joinGroup(mcastAddr, networkInterface)
        // Using scapy to generate IGMPv3 membership report:
        // ether = Ether(src='02:03:04:05:06:07', dst='01:00:5e:00:00:16')
        // ip = IP(src='0.0.0.0', dst='224.0.0.22', id=0, flags='DF', options=[IPOption_Router_Alert()])
        // igmp = IGMPv3(type=0x22)/IGMPv3mr(records=[IGMPv3gr(rtype=4, maddr='239.0.0.1')])
        // pkt = ether/ip/igmp
        val joinReport = """
            01005e000016020304050607080046c0002800004000010203fa00000000e0000016940400002200ea
            fc0000000104000000ef000001
        """.replace("\\s+".toRegex(), "").trim()
        val srcMac = ifParams.macAddr.toString().replace(":", "")
        val expectedJoinPkt = HexDump.hexStringToByteArray(
            joinReport.replace("020304050607", srcMac)
        )
        assertNextPacketEquals(socket, expectedJoinPkt, "IGMPv3 join report")

        multicastSock.leaveGroup(mcastAddr, networkInterface)
        // Using scapy to generate IGMPv3 membership report:
        // ether = Ether(src='02:03:04:05:06:07', dst='01:00:5e:00:00:16')
        // ip = IP(src='0.0.0.0', dst='224.0.0.22', id=0, flags='DF', options=[IPOption_Router_Alert()])
        // igmp = IGMPv3(type=0x22)/IGMPv3mr(records=[IGMPv3gr(rtype=3, maddr='239.0.0.1')])
        // pkt = ether/ip/igmp
        val leaveReport = """
            01005e000016020304050607080046c0002800004000010203fa00000000e0000016940400002200eb
            fc0000000103000000ef000001
        """.replace("\\s+".toRegex(), "").trim()
        val expectedLeavePkt = HexDump.hexStringToByteArray(
            leaveReport.replace("020304050607", srcMac)
        )
        assertNextPacketEquals(socket, expectedLeavePkt, "IGMPv3 leave report")
    }

    @Test
    fun testAttachEgressMulticastReportFilter() {
        val socket = Os.socket(AF_PACKET, SOCK_RAW or SOCK_CLOEXEC, 0)
        val ifParams = InterfaceParams.getByName(iface.interfaceName)
            ?: fail("Could not obtain interface params for ${iface.interfaceName}")
        val socketAddr = SocketUtils.makePacketSocketAddress(ETH_P_ALL, ifParams.index)
        NetworkStackUtils.attachEgressMulticastReportFilter(socket)
        Os.bind(socket, socketAddr)
        Os.setsockoptTimeval(
            socket,
            SOL_SOCKET,
            SO_RCVTIMEO,
            StructTimeval.fromMillis(TEST_TIMEOUT_MS)
        )

        val sendSocket = Os.socket(AF_PACKET, SOCK_RAW or SOCK_CLOEXEC, 0)
        Os.bind(sendSocket, socketAddr)

        testExpectedPacketsReceived(sendSocket, socket)

        // Using scapy to generate MLDv1 membership report:
        // ether = Ether(src='02:03:04:05:06:07', dst='33:33:33:11:11:11')
        // ipv6 = IPv6(src='fe80::fc01:83ff:fea6:378b', dst='ff12::1:1111:1111', hlim=1)
        // option = IPv6ExtHdrHopByHop(options=[RouterAlert(otype=5)])
        // mld = ICMPv6MLReport(type=131, mladdr='ff12::1:1111:1111')
        // pkt = ether/ipv6/option/mld
        val mldv1ReportHexStr = """
            33333311111102030405060786dd6000000000200001fe80000000000000fc0183fffea6378bff12000000
            00000000000001111111113a000502000001008300858c00000000ff120000000000000000000111111111
        """.replace("\\s+".toRegex(), "").trim()
        val mldv1Report = HexDump.hexStringToByteArray(mldv1ReportHexStr)
        Os.write(sendSocket, mldv1Report, 0, mldv1Report.size)
        assertUntilPacketEquals(socket, mldv1Report, "MLDv1 report")

        // Using scapy to generate MLDv1 membership done:
        // ether = Ether(src='02:03:04:05:06:07', dst='33:33:33:00:00:02')
        // ipv6 = IPv6(src='fe80::fc01:83ff:fea6:378b', dst='ff02::2', hlim=1)
        // option = IPv6ExtHdrHopByHop(options=[RouterAlert(otype=5)])
        // mld = ICMPv6MLReport(type=132, mladdr='ff12::1:1111:1111')
        // pkt = ether/ipv6/option/mld
        val mldv1DoneHexStr = """
            33333300000202030405060786dd6000000000200001fe80000000000000fc0183fffea6378bff02000000
            00000000000000000000023a000502000001008400a6bd00000000ff120000000000000000000111111111
        """.replace("\\s+".toRegex(), "").trim()
        val mldv1Done = HexDump.hexStringToByteArray(mldv1DoneHexStr)
        Os.write(sendSocket, mldv1Done, 0, mldv1Done.size)
        assertUntilPacketEquals(socket, mldv1Done, "MLDv1 done")

        // Using scapy to generate MLDv2 membership report:
        // ether = Ether(src='02:03:04:05:06:07', dst='33:33:33:00:00:16')
        // ipv6 = IPv6(src='fe80::fc01:83ff:fea6:378b', dst='ff02::16', hlim=1)
        // option = IPv6ExtHdrHopByHop(options=[RouterAlert(otype=5)])
        // mld = ICMPv6MLReport2(records=[ICMPv6MLDMultAddrRec(dst='ff12::1:1111:1111')])
        // pkt = ether/ipv6/option/mld
        val mldv2ReportHexStr = """
            33333300001602030405060786dd6000000000240001fe80000000000000fc0183fffea6378bff02000000
            00000000000000000000163a000502000001008f0097a40000000104000000ff1200000000000000000001
        11111111
        """.replace("\\s+".toRegex(), "").trim()
        val mldv2Report = HexDump.hexStringToByteArray(mldv2ReportHexStr)
        Os.write(sendSocket, mldv2Report, 0, mldv2Report.size)
        assertUntilPacketEquals(socket, mldv2Report, "MLDv2 report")

        // shorten the socket timeout to prevent waiting too long in the test
        Os.setsockoptTimeval(socket, SOL_SOCKET, SO_RCVTIMEO, StructTimeval.fromMillis(100))

        testExpectedPacketsNotReceived(sendSocket, socket)

        // Using scapy to generate MLDv1 general query packet:
        //   ether = Ether(src='02:03:04:05:06:07', dst='33:33:33:00:00:01')
        //   ipv6 = IPv6(src='fe80::fc01:83ff:fea6:378b', dst='ff02::1', hlim=1)
        //   option = IPv6ExtHdrHopByHop(options=[RouterAlert(otype=5)])
        //   mld = ICMPv6MLQuery()
        //   pkt = ether/ipv6/option/mld
        val mldv1GqHexStr = """
            33333300000102030405060786dd6000000000200001fe80000000000000fc0183fffea6378bff02000000
            00000000000000000000013a000502000001008200a2e42710000000000000000000000000000000000000
        """.replace("\\s+".toRegex(), "").trim()
        val mldv1Gq = HexDump.hexStringToByteArray(mldv1GqHexStr)
        Os.write(sendSocket, mldv1Gq, 0, mldv1Gq.size)
        assertUntilSocketReadErrno(
            "MLDv1 General Query Packet should not been received",
            socket,
            OsConstants.EAGAIN
        )

        // Using scapy to generate MLDv2 general query packet:
        //   ether = Ether(src='02:03:04:05:06:07', dst='33:33:33:00:00:01')
        //   ipv6 = IPv6(src='fe80::fc01:83ff:fea6:378b', dst='ff02::1', hlim=1)
        //   option = IPv6ExtHdrHopByHop(options=[RouterAlert(otype=5)])
        //   mld = ICMPv6MLQuery2()
        //   pkt = ether/ipv6/option/mld
        val mldv2GqHexStr = """
            33333300000102030405060786dd6000000000240001fe80000000000000fc0183fffea6378bff02000000
            00000000000000000000013a000502000001008200a2e02710000000000000000000000000000000000000
            00000000
        """.replace("\\s+".toRegex(), "").trim()
        val mldv2Gq = HexDump.hexStringToByteArray(mldv2GqHexStr)
        Os.write(sendSocket, mldv2Gq, 0, mldv1Gq.size)
        assertUntilSocketReadErrno(
            "MLDv2 General Query Packet should not been received",
            socket,
            OsConstants.EAGAIN
        )
    }

    private fun testExpectedPacketsReceived(
        sendSocket: FileDescriptor,
        recvSocket: FileDescriptor
    ) {
        // Using scapy to generate IGMPv2 membership report:
        // ether = Ether(src='02:03:04:05:06:07', dst='01:00:5e:00:00:01')
        // ip = IP(src='10.0.0.1', dst='239.0.0.1', id=0, flags='DF', tos=0xc0, options=[IPOption_Router_Alert()])
        // igmp = IGMP(type=0x16, mrcode=0, gaddr='239.0.0.1')
        // pkt = ether/ip/igmp
        val igmpv2ReportHexStr = """
            01005e000001020304050607080046c00020000040000102eb150a000001ef000001940400001600fafd
            ef000001
        """.replace("\\s+".toRegex(), "").trim()
        val igmpv2Report = HexDump.hexStringToByteArray(igmpv2ReportHexStr)
        Os.write(sendSocket, igmpv2Report, 0, igmpv2Report.size)
        assertUntilPacketEquals(recvSocket, igmpv2Report, "IGMPv2 report")

        // Using scapy to generate IGMPv2 membership leave report:
        // ether = Ether(src='02:03:04:05:06:07', dst='01:00:5e:00:00:01')
        // ip = IP(src='10.0.0.1', dst='239.0.0.1', id=0, flags='DF', tos=0xc0, options=[IPOption_Router_Alert()])
        // igmp = IGMP(type=0x17, mrcode=0, gaddr='239.0.0.1')
        // pkt = ether/ip/igmp
        val igmpv2LeaveHexStr = """
            01005e000001020304050607080046c00020000040000102eb150a000001ef000001940400001700f9fd
            ef000001
        """.replace("\\s+".toRegex(), "").trim()
        val igmpv2Leave = HexDump.hexStringToByteArray(igmpv2LeaveHexStr)
        Os.write(sendSocket, igmpv2Leave, 0, igmpv2Leave.size)
        assertUntilPacketEquals(recvSocket, igmpv2Leave, "IGMPv2 leave")

        // Using scapy to generate IGMPv3 membership report:
        // ether = Ether(src='02:03:04:05:06:07', dst='01:00:5e:00:00:16')
        // ip = IP(src='10.0.0.1', dst='224.0.0.22', id=0, flags='DF', options=[IPOption_Router_Alert()])
        // igmp = IGMPv3(type=0x22)/IGMPv3mr(records=[IGMPv3gr(rtype=2, maddr='239.0.0.1')])
        // pkt = ether/ip/igmp
        val igmpv3ReportHexStr = """
            01005e000016020304050607080046c00028000040000102f9f80a000001e0000016940400002200ecfc
            0000000102000000ef000001
        """.replace("\\s+".toRegex(), "").trim()
        val igmpv3Report = HexDump.hexStringToByteArray(igmpv3ReportHexStr)
        Os.write(sendSocket, igmpv3Report, 0, igmpv3Report.size)
        assertUntilPacketEquals(recvSocket, igmpv3Report, "IGMPv3 report")
    }

    private fun testExpectedPacketsNotReceived(
        sendSocket: FileDescriptor,
        recvSocket: FileDescriptor
    ) {
        val dhcpNak = DhcpPacket.buildNakPacket(
            DhcpPacket.ENCAP_L2,
            42,
            TEST_TARGET_IPV4_ADDR, /*relayIp=*/
            IPV4_ADDR_ANY,
            TEST_TARGET_MAC.toByteArray(),
            /*broadcast=*/
            false,
            "NAK"
        ).readAsArray()
        Os.write(sendSocket, dhcpNak, 0, dhcpNak.size)
        assertUntilSocketReadErrno(
            "DHCP Packet should not been received",
            recvSocket,
            OsConstants.EAGAIN
        )

        // Using scapy to generate IGMPv2 general query packet:
        //   ether = Ether(src='02:03:04:05:06:07', dst='01:00:5e:00:00:01')
        //   ip = IP(src='10.0.0.1', dst='239.0.0.1', id=0, flags='DF', tos=0xc0, options=[IPOption_Router_Alert()])
        //   igmp = IGMP(type=0x11)
        //   pkt = ether/ip/igmp
        val igmpv2GqHexStr = """
            01005e000001020304050607080046c00020000040000102eb150a000001ef000001940400001114eeeb
            00000000
        """.replace("\\s+".toRegex(), "").trim()
        val igmpv2Gq = HexDump.hexStringToByteArray(igmpv2GqHexStr)
        Os.write(sendSocket, igmpv2Gq, 0, igmpv2Gq.size)
        assertUntilSocketReadErrno(
            "IGMPv2 General Query Packet should not been received",
            recvSocket,
            OsConstants.EAGAIN
        )

        // Using scapy to generate IGMPv1 general query packet:
        //   ether = Ether(src='02:03:04:05:06:07', dst='01:00:5e:00:00:01')
        //   ip = IP(src='10.0.0.1', dst='239.0.0.1', id=0, flags='DF', tos=0xc0, options=[IPOption_Router_Alert()])
        //   igmp = IGMP(type=0x11, mrcode=0)
        //   pkt = ether/ip/igmp
        val igmpv1GqHexStr = """
            01005e000001020304050607080046c00020000040000102eb150a000001ef000001940400001100eeff
            00000000
        """.replace("\\s+".toRegex(), "").trim()
        val igmpv1Gq = HexDump.hexStringToByteArray(igmpv1GqHexStr)
        Os.write(sendSocket, igmpv1Gq, 0, igmpv1Gq.size)
        assertUntilSocketReadErrno(
            "IGMPv1 General Query Packet should not been received",
            recvSocket,
            OsConstants.EAGAIN
        )
    }

    private fun assertUntilPacketEquals(
        socket: FileDescriptor,
        expected: ByteArray,
        descr: String
    ) {
        val buffer = ByteArray(TEST_MTU)
        var readBytes: Int
        var actualPkt: ByteArray? = null
        while (Os.read(socket, buffer, 0 /* byteOffset */, buffer.size)
            .also { readBytes = it } > 0
        ) {
            actualPkt = buffer.copyOfRange(0, readBytes)
            if (!isTestInterfaceEgressPacket(actualPkt)) break
        }

        assertNotNull(actualPkt, "no received packets")
        assertArrayEquals(
            "Received packet(${HexDump.toHexString(actualPkt)}) " +
            "!= expected(${HexDump.toHexString(expected)}) $descr",
            expected,
            actualPkt
        )
    }

    private fun assertUntilSocketReadErrno(msg: String, socket: FileDescriptor, errno: Int) {
        val buffer = ByteArray(TEST_MTU)
        var readBytes: Int
        var actualPkt: ByteArray? = null
        try {
            while (Os.read(socket, buffer, 0 /* byteOffset */, buffer.size)
                    .also { readBytes = it } > 0
            ) {
                actualPkt = buffer.copyOfRange(0, readBytes)
                if (!isTestInterfaceEgressPacket(actualPkt)) break
            }
            fail(msg + ": " + HexDump.toHexString(actualPkt))
        } catch (expected: ErrnoException) {
            assertEquals(errno.toLong(), expected.errno.toLong())
        }
    }

    private fun assertNextPacketEquals(socket: FileDescriptor, expected: ByteArray, descr: String) {
        val buffer = ByteArray(TEST_MTU)
        val readPacket = Os.read(socket, buffer, 0 /* byteOffset */, buffer.size)
        assertTrue(readPacket > 0, "$descr not received")
        assertEquals(expected.size, readPacket, "Received packet size does not match for $descr")
        assertArrayEquals(
            "Received packet != expected $descr",
            expected,
            buffer.copyOfRange(0, readPacket)
        )
    }

    private fun assertSolicitedNodeMulticastAddress(
        expected: Inet6Address?,
        unicast: Inet6Address
    ) {
        assertNotNull(expected)
        val prefix = IpPrefix(SOLICITED_NODE_MULTICAST_PREFIX)
        assertTrue(prefix.contains(expected))
        assertTrue(expected.isMulticastAddress())
        // check the last 3 bytes of address
        assertArrayEquals(
            Arrays.copyOfRange(expected.getAddress(), 13, 15),
            Arrays.copyOfRange(unicast.getAddress(), 13, 15)
        )
    }

    @Test
    fun testConvertIpv6AddressToSolicitedNodeMulticast() {
        val addr1 = NetworkStackUtils.ipv6AddressToSolicitedNodeMulticast(TEST_INET6ADDR_1)
        assertSolicitedNodeMulticastAddress(addr1, TEST_INET6ADDR_1)

        val addr2 = NetworkStackUtils.ipv6AddressToSolicitedNodeMulticast(TEST_INET6ADDR_2)
        assertSolicitedNodeMulticastAddress(addr2, TEST_INET6ADDR_2)

        val addr3 = NetworkStackUtils.ipv6AddressToSolicitedNodeMulticast(TEST_INET6ADDR_3)
        assertSolicitedNodeMulticastAddress(addr3, TEST_INET6ADDR_3)
    }

    @Test
    fun testConvertMacAddressToEui64() {
        // MAC address with universal/local bit set (the first byte: 0xBA)
        var expected = byteArrayOf(
            0xB8.toByte(),
            0x98.toByte(),
            0x76.toByte(),
            0xFF.toByte(),
            0xFE.toByte(),
            0x54.toByte(),
            0x32.toByte(),
            0x10.toByte()
        )
        val srcEui64 = NetworkStackUtils.macAddressToEui64(TEST_SRC_MAC)
        assertArrayEquals(expected, srcEui64)

        // MAC address with universal/local bit unset (the first byte: 0x01).
        expected = byteArrayOf(
                0x03.toByte(), 0x23.toByte(), 0x45.toByte(), 0xFF.toByte(),
                0xFE.toByte(), 0x67.toByte(), 0x89.toByte(), 0x0A.toByte())
        val targetEui64 = NetworkStackUtils.macAddressToEui64(TEST_TARGET_MAC)
        assertArrayEquals(expected, targetEui64)
    }

    @Test
    fun testGenerateIpv6AddressFromEui64() {
        val eui64 = NetworkStackUtils.macAddressToEui64(TEST_SRC_MAC)
        var prefix = IpPrefix("2001:db8:1::/80")
        // Don't accept the prefix length larger than 64.
        assertNull(NetworkStackUtils.createInet6AddressFromEui64(prefix, eui64))

        // prefix length equals to or less than 64 is acceptable.
        prefix = IpPrefix("2001:db8:1::/48")
        // IPv6 address string is formed by combining the IPv6 prefix("2001:db8:1::") and
        // EUI64 converted from TEST_SRC_MAC, see above test for the output EUI64 example.
        var expected = parseNumericAddress("2001:db8:1::b898:76ff:fe54:3210") as Inet6Address
        assertEquals(expected, NetworkStackUtils.createInet6AddressFromEui64(prefix, eui64))

        prefix = IpPrefix("2001:db8:1:2::/64")
        expected = parseNumericAddress("2001:db8:1:2:b898:76ff:fe54:3210") as Inet6Address
        assertEquals(expected, NetworkStackUtils.createInet6AddressFromEui64(prefix, eui64))
    }

    private fun assertSocketReadErrno(msg: String, fd: FileDescriptor, errno: Int) {
        val received = ByteBuffer.allocate(TEST_MTU)
        try {
            val len = Os.read(fd, received)
            fail(msg + ": " + toHexString(received, len))
        } catch (expected: ErrnoException) {
            assertEquals(errno.toLong(), expected.errno.toLong())
        }
    }

    private fun assertNextPacketOnSocket(fd: FileDescriptor, expectedPacket: ByteBuffer) {
        val received = ByteBuffer.allocate(TEST_MTU)
        val len = Os.read(fd, received)
        assertEquals(
            toHexString(expectedPacket, expectedPacket.limit()),
            toHexString(received, len)
        )
    }

    private fun setMfBit(packet: ByteBuffer, set: Boolean) {
        val offset = ETHER_HEADER_LEN + IPV4_FLAGS_OFFSET
        var flagOff: Int = packet.getShort(offset).toInt()
        if (set) {
            flagOff = (flagOff or IPV4_FLAG_MF) and IPV4_FLAG_DF.inv()
        } else {
            flagOff = (flagOff or IPV4_FLAG_DF) and IPV4_FLAG_MF.inv()
        }
        packet.putShort(offset, flagOff.toShort())
        // Recalculate the checksum, which requires first clearing the checksum field.
        val checksumOffset = ETHER_HEADER_LEN + IPV4_CHECKSUM_OFFSET
        packet.putShort(checksumOffset, 0)
        packet.putShort(checksumOffset, IpUtils.ipChecksum(packet, ETHER_HEADER_LEN))
    }

    private fun isTestInterfaceEgressPacket(packet: ByteArray): Boolean {
        val srcMac = packet.copyOfRange(
            ETHER_SRC_ADDR_OFFSET,
            ETHER_SRC_ADDR_OFFSET + ETHER_ADDR_LEN
        )
        val ifParams = InterfaceParams.getByName(iface.interfaceName)
        return srcMac.contentEquals(ifParams.macAddr.toByteArray())
    }

    private fun doTestDhcpResponseWithMfBitDropped(generic: Boolean) {
        val ifindex = InterfaceParams.getByName(iface.interfaceName).index
        val packetSock = Os.socket(AF_PACKET, SOCK_RAW or SOCK_NONBLOCK, /*protocol=*/0)
        try {
            if (generic) {
                NetworkStackUtils.attachControlPacketFilter(packetSock)
            } else {
                NetworkStackUtils.attachDhcpFilter(packetSock)
            }
            val addr = SocketUtils.makePacketSocketAddress(OsConstants.ETH_P_IP, ifindex)
            Os.bind(packetSock, addr)
            val packet = DhcpPacket.buildNakPacket(
                DhcpPacket.ENCAP_L2,
                42,
                TEST_TARGET_IPV4_ADDR, /*relayIp=*/
                IPV4_ADDR_ANY,
                TEST_TARGET_MAC.toByteArray(),
                /*broadcast=*/
                false,
                "NAK"
            )
            setMfBit(packet, true)
            reader.sendResponse(packet)

            // Packet with MF bit set is not received.
            assertSocketReadErrno(
                "Packet with MF bit should have been dropped",
                packetSock,
                OsConstants.EAGAIN
            )

            // Identical packet, except with MF bit cleared, should be received.
            setMfBit(packet, false)
            reader.sendResponse(packet)
            assertNextPacketOnSocket(packetSock, packet)
        } finally {
            Os.close(packetSock)
        }
    }

    @Test
    fun testDhcpResponseWithMfBitDropped() {
        doTestDhcpResponseWithMfBitDropped(false)
    }

    @Test
    fun testGenericDhcpResponseWithMfBitDropped() {
        doTestDhcpResponseWithMfBitDropped(true)
    }

    @Test
    fun testConvertIpv4AddressToEthernetMulticast() {
        var mcastAddrs = listOf(
            // ipv4 multicast address, multicast ethernet address
            Pair(
                InetAddress.getByName("224.0.0.1") as Inet4Address,
                MacAddress.fromString("01:00:5e:00:00:01")
            ),
            Pair(
                InetAddress.getByName("239.128.1.1") as Inet4Address,
                MacAddress.fromString("01:00:5e:00:01:01")
            ),
            Pair(
                InetAddress.getByName("239.255.255.255") as Inet4Address,
                MacAddress.fromString("01:00:5e:7f:ff:ff")
            )
        )

        for ((addr, expectAddr) in mcastAddrs) {
            val ether = NetworkStackUtils.ipv4MulticastToEthernetMulticast(addr)
            assertEquals(expectAddr, ether)
        }
    }

    @Test
    fun testSelectPreferredIPv6LinkLocalAddress() {
        val addr1 = LinkAddress("fe80::1/64", IFA_F_TENTATIVE, RT_SCOPE_LINK)
        val addr2 = LinkAddress("fe80::2/64", 0 /* flags */, RT_SCOPE_LINK)
        val addr3 = LinkAddress("fe80::3/64", IFA_F_DEPRECATED, RT_SCOPE_LINK)

        val lp1 = LinkProperties()
        lp1.setLinkAddresses(listOf(addr1, addr2, addr3))
        assertEquals(addr2.address, NetworkStackUtils.selectPreferredIPv6LinkLocalAddress(lp1))

        val lp2 = LinkProperties()
        lp2.setLinkAddresses(listOf(addr1, addr3))
        assertEquals(addr3.address, NetworkStackUtils.selectPreferredIPv6LinkLocalAddress(lp2))

       val lp3 = LinkProperties()
        lp3.setLinkAddresses(listOf(addr1))
        assertNull(NetworkStackUtils.selectPreferredIPv6LinkLocalAddress(lp3))
    }
}

private fun ByteBuffer.readAsArray(): ByteArray {
    val out = ByteArray(remaining())
    get(out)
    return out
}

private fun toHexString(b: ByteBuffer, len: Int): String {
    return HexDump.toHexString(Arrays.copyOf(b.array(), len))
}

private fun <T : Any> Context.assertHasService(manager: KClass<T>) = getSystemService(manager.java)
        ?: fail("Could not find service $manager")

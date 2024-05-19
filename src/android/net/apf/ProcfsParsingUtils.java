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

import android.util.Log;

import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.util.HexDump;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public final class ProcfsParsingUtils {
    public static final String TAG = ProcfsParsingUtils.class.getSimpleName();

    private static final String IPV6_CONF_PATH = "/proc/sys/net/ipv6/conf/";
    private static final String IPV6_ANYCAST_PATH = "/proc/net/anycast6";

    private ProcfsParsingUtils() {
    }

    /**
     * Reads the contents of a text file line by line.
     *
     * @param filePath The absolute path to the file to read.
     * @return A List of Strings where each String represents a line from the file.
     *         If an error occurs during reading, an empty list is returned, and an error is logged.
     */
    private static List<String> readFile(final String filePath) {
        final List<String> lines = new ArrayList<>();
        try (BufferedReader reader =
                     Files.newBufferedReader(Paths.get(filePath), StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }
        } catch (IOException e) {
            Log.wtf(TAG, "failed to read " + filePath, e);
        }

        return lines;
    }

    /**
     * Parses the Neighbor Discovery traffic class from a list of strings.
     *
     * This function expects a list containing a single string representing the ND traffic class.
     * If the list is empty or contains multiple lines, it assumes a default traffic class of 0.
     *
     * @param lines A list of strings, ideally containing one line with the ND traffic class.
     * @return The parsed ND traffic class as an integer, or 0 if the input is invalid.
     */
    @VisibleForTesting
    public static int parseNdTrafficClass(final List<String> lines) {
        if (lines.size() != 1) {
            return 0;   // default
        }

        return Integer.parseInt(lines.get(0));
    }

    /**
     * Parses an anycast6 address associated with a specific interface from a list of strings.
     *
     * This function searches the input list for a line containing the specified interface name.
     * If found, it extracts the IPv6 address from that line and
     * converts it into an `Inet6Address` object.
     *
     * @param lines   A list of strings where each line is expected to contain
     *                interface and address information.
     * @param ifname  The name of the network interface to search for.
     * @return       The parsed `Inet6Address` representing the anycast address
     *               associated with the specified interface,
     *               or `null` if no matching line is found or if an error occurs during parsing.
     */
    @VisibleForTesting
    public static Inet6Address parseAnycast6Address(final List<String> lines, final String ifname) {
        try {
            for (String line : lines) {
                if (!line.contains(ifname)) {
                    continue;
                }

                // If there's multiple anycast addresses, only the first one will be returned.
                // It only has one anycast address per interface for clat.
                final String[] fields = line.split(" ");
                final byte[] addr = HexDump.hexStringToByteArray(fields[2]);
                return (Inet6Address) InetAddress.getByAddress(addr);
            }
        } catch (UnknownHostException e) {
            Log.wtf("failed to convert to Inet6Address.", e);
            return null;
        }
        return null;
    }

    /**
     * Returns the traffic class for the specified interface.
     * The function loads the existing traffic class from the file
     * `/proc/sys/net/ipv6/conf/{ifname}/ndisc_tclass`. If the file does not exist, the
     * function returns 0.
     *
     * @param ifname The name of the interface.
     * @return The traffic class for the interface.
     */
    public static int getNdTrafficClass(final String ifname) {
        final String ndTcPath = IPV6_CONF_PATH + ifname + "/ndisc_tclass";
        final List<String> lines = readFile(ndTcPath);
        return parseNdTrafficClass(lines);
    }

    /**
     * The function loads the existing IPv6 anycast address from the file `/proc/net/anycast6`.
     * If the file does not exist or the interface is not found, the function
     * returns null.
     *
     * @param ifname The name of the interface.
     * @return The IPv6 anycast address for the interface.
     */
    public static Inet6Address getAnycast6Address(final String ifname) {
        final List<String> lines = readFile(IPV6_ANYCAST_PATH);
        return parseAnycast6Address(lines, ifname);
    }
}

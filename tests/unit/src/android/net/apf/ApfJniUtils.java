/*
 * Copyright (C) 2023 The Android Open Source Project
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

import java.util.List;

/**
 * The class contains the helper method for interacting with native apf code.
 */
public class ApfJniUtils {
    static final int APF_INTERPRETER_VERSION_V6 = 6000;
    static final int APF_INTERPRETER_VERSION_NEXT = 99999999;
    public ApfJniUtils(int apfInterpreterVersion) {
        // Load up native shared library containing APF interpreter exposed via JNI.
        if (apfInterpreterVersion == APF_INTERPRETER_VERSION_V6) {
            System.loadLibrary("apfjniv6");
        } else if (apfInterpreterVersion == APF_INTERPRETER_VERSION_NEXT) {
            System.loadLibrary("apfjninext");
        } else {
            throw new IllegalArgumentException(
                "apfInterpreterVersion must be "
                    + APF_INTERPRETER_VERSION_V6 + " or "
                    + APF_INTERPRETER_VERSION_NEXT);
        }
    }

    /**
     * Call the APF interpreter to run {@code program} on {@code packet} with persistent memory
     * segment {@data} pretending the filter was installed {@code filter_age} seconds ago.
     */
    public native int apfSimulate(int apfVersion, byte[] program, byte[] packet,
            byte[] data, int filterAge);

    /**
     * Compile a tcpdump human-readable filter (e.g. "icmp" or "tcp port 54") into a BPF
     * prorgam and return a human-readable dump of the BPF program identical to "tcpdump -d".
     */
    public native String compileToBpf(String filter);

    /**
     * Open packet capture file {@code pcap_filename} and filter the packets using tcpdump
     * human-readable filter (e.g. "icmp" or "tcp port 54") compiled to a BPF program and
     * at the same time using APF program {@code apf_program}.  Return {@code true} if
     * both APF and BPF programs filter out exactly the same packets.
     */
    public native boolean compareBpfApf(int apfVersion, String filter,
            String pcapFilename, byte[] apfProgram);

    /**
     * Open packet capture file {@code pcapFilename} and run it through APF filter. Then
     * checks whether all the packets are dropped and populates data[] {@code data} with
     * the APF counters.
     */
    public native boolean dropsAllPackets(int apfVersion, byte[] program, byte[] data,
            String pcapFilename);

    /**
     * Disassemble the Apf program into human-readable text.
     */
    public native String[] disassembleApf(byte[] program);

    /**
     * Get all transmitted packets.
     */
    public native List<byte[]> getAllTransmittedPackets();

    /**
     * Reset the memory region that stored the transmitted packet.
     */
    public native void resetTransmittedPacketMemory();
}

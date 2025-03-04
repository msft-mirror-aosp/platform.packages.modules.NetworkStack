/*
 * Copyright (C) 2025 The Android Open Source Project
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

/**
 * APFv6.1 assembler/generator. A tool for generating an APFv6.1 program.
 *
 * @hide
 */
public final class ApfV61Generator extends ApfV61GeneratorBase<ApfV61Generator> {
    /**
     * Returns true if we support the specified {@code version}, otherwise false.
     */
    public static boolean supportsVersion(int version) {
        return version >= APF_VERSION_61;
    }

    /**
     * Creates an ApfV61Generator instance.
     */
    public ApfV61Generator(int version, int ramSize, int clampSize)
            throws IllegalInstructionException {
        super(new byte[0], version, ramSize, clampSize);
    }
}

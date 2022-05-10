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

package com.android.networkstack.apishim.api30;

import static com.android.modules.utils.build.SdkLevel.isAtLeastR;

import android.net.util.SocketUtils;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import com.android.networkstack.apishim.common.SocketUtilsShim;

import java.net.SocketAddress;

/**
 * Implementation of {@link SocketUtilsShim} for API 30.
 */
@RequiresApi(Build.VERSION_CODES.R)
public class SocketUtilsShimImpl
        extends com.android.networkstack.apishim.api29.SocketUtilsShimImpl {
    protected SocketUtilsShimImpl() {}

    /**
     * Get a new instance of {@link SocketUtilsShim}.
     */
    @RequiresApi(Build.VERSION_CODES.Q)
    public static SocketUtilsShim newInstance() {
        if (!isAtLeastR()) {
            return com.android.networkstack.apishim.api29.SocketUtilsShimImpl.newInstance();
        }
        return new SocketUtilsShimImpl();
    }

    @NonNull
    @Override
    public SocketAddress makePacketSocketAddress(
            int protocol, int ifIndex, @NonNull byte[] hwAddr) {
        return SocketUtils.makePacketSocketAddress(protocol, ifIndex, hwAddr);
    }
}

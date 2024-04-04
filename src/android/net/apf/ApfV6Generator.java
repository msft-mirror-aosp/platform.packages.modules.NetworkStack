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

import static android.net.apf.BaseApfGenerator.Register.R1;

import com.android.internal.annotations.VisibleForTesting;

/**
 * APFv6 assembler/generator. A tool for generating an APFv6 program.
 *
 * @hide
 */
public final class ApfV6Generator extends ApfV6GeneratorBase<ApfV6Generator> {
    /**
     * Creates an ApfV6Generator instance which is able to emit instructions for the specified
     * {@code version} of the APF interpreter. Throws {@code IllegalInstructionException} if
     * the requested version is unsupported.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public ApfV6Generator() throws IllegalInstructionException {
        super();
    }

    @Override
    void addArithR1(Opcodes opcode) {
        append(new Instruction(opcode, R1));
    }

    /**
     * Add an instruction to the end of the program to increment the counter value and
     * immediately return PASS.
     *
     * @param counter the counter enum to be incremented.
     */
    @Override
    public ApfV6Generator addCountAndPass(ApfCounterTracker.Counter counter) {
        checkPassCounterRange(counter);
        return addCountAndPass(counter.value());
    }

    /**
     * Add an instruction to the end of the program to increment the counter value and
     * immediately return DROP.
     *
     * @param counter the counter enum to be incremented.
     */
    @Override
    public ApfV6Generator addCountAndDrop(ApfCounterTracker.Counter counter) {
        checkDropCounterRange(counter);
        return addCountAndDrop(counter.value());
    }

    @Override
    public ApfV6Generator addCountAndDropIfR0Equals(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        checkDropCounterRange(cnt);
        final String tgt = getUniqueLabel();
        return addJumpIfR0NotEquals(val, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndPassIfR0Equals(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        checkPassCounterRange(cnt);
        final String tgt = getUniqueLabel();
        return addJumpIfR0NotEquals(val, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndDropIfR0NotEquals(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        checkDropCounterRange(cnt);
        final String tgt = getUniqueLabel();
        return addJumpIfR0Equals(val, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndPassIfR0NotEquals(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        checkPassCounterRange(cnt);
        final String tgt = getUniqueLabel();
        return addJumpIfR0Equals(val, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndDropIfR0LessThan(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        checkDropCounterRange(cnt);
        if (val <= 0) {
            throw new IllegalArgumentException("val must > 0, current val: " + val);
        }
        final String tgt = getUniqueLabel();
        return addJumpIfR0GreaterThan(val - 1, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndPassIfR0LessThan(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        checkPassCounterRange(cnt);
        if (val <= 0) {
            throw new IllegalArgumentException("val must > 0, current val: " + val);
        }
        final String tgt = getUniqueLabel();
        return addJumpIfR0GreaterThan(val - 1, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndDropIfBytesAtR0NotEqual(byte[] bytes,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        checkDropCounterRange(cnt);
        final String tgt = getUniqueLabel();
        return addJumpIfBytesAtR0Equal(bytes, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    private int mLabelCount = 0;

    /**
     * Return a unique label string.
     */
    private String getUniqueLabel() {
        return "LABEL_" + mLabelCount++;
    }

    /**
     * This method is noop in APFv6.
     */
    @Override
    public ApfV6Generator addCountTrampoline() {
        return self();
    }
}

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
package android.net.apf

import android.net.apf.ApfGenerator.IllegalInstructionException
import androidx.test.filters.SmallTest
import androidx.test.runner.AndroidJUnit4
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Tests for APFv6 specific instructions.
 */
@RunWith(AndroidJUnit4::class)
@SmallTest
class ApfV5Test {

    @Test
    fun testApfInstructionVersionCheck() {
        var gen = ApfGenerator(ApfGenerator.MIN_APF_VERSION)
        assertFailsWith<IllegalInstructionException> { gen.addDrop() }
    }

    @Test
    fun testApfInstructionsEncoding() {
        var gen = ApfGenerator(ApfGenerator.MIN_APF_VERSION)
        gen.addPass()
        var program = gen.generate()
        // encoding PASS opcode: opcode=0, imm_len=0, R=0
        assertContentEquals(byteArrayOf(encodeInstruction(0, 0, 0)), program)

        gen = ApfGenerator(ApfGenerator.MIN_APF_VERSION_IN_DEV)
        gen.addDrop()
        program = gen.generate()
        // encoding DROP opcode: opcode=0, imm_len=0, R=1
        assertContentEquals(byteArrayOf(encodeInstruction(0, 0, 1)), program)

        gen = ApfGenerator(ApfGenerator.MIN_APF_VERSION_IN_DEV)
        gen.addAlloc(ApfGenerator.Register.R0)
        program = gen.generate()
        assertContentEquals(byteArrayOf(encodeInstruction(21, 1, 0), 36), program)
        assertContentEquals(arrayOf("       0: alloc r0"), ApfJniUtils.disassembleApf(program))

        gen = ApfGenerator(ApfGenerator.MIN_APF_VERSION_IN_DEV)
        gen.addTrans(ApfGenerator.Register.R1)
        program = gen.generate()
        assertContentEquals(byteArrayOf(encodeInstruction(21, 1, 1), 37), program)
        assertContentEquals(arrayOf("       0: trans r1"), ApfJniUtils.disassembleApf(program))

        gen = ApfGenerator(ApfGenerator.MIN_APF_VERSION_IN_DEV)
        gen.addWrite(0x01, 1)
        gen.addWrite(0x0102, 2)
        gen.addWrite(0x01020304, 4)
        program = gen.generate()
        assertContentEquals(byteArrayOf(
                encodeInstruction(24, 1, 0), 0x01,
                encodeInstruction(24, 2, 0), 0x01, 0x02,
                encodeInstruction(24, 4, 0), 0x01, 0x02, 0x03, 0x04
        ), program)
        assertContentEquals(arrayOf(
                "       0: write 0x01",
                "       2: write 0x0102",
                "       5: write 0x01020304"), ApfJniUtils.disassembleApf(program))

        gen = ApfGenerator(ApfGenerator.MIN_APF_VERSION_IN_DEV)
        gen.addWrite(ApfGenerator.Register.R0, 1)
        gen.addWrite(ApfGenerator.Register.R0, 2)
        gen.addWrite(ApfGenerator.Register.R0, 4)
        program = gen.generate()
        assertContentEquals(byteArrayOf(
                encodeInstruction(21, 1, 0), 38,
                encodeInstruction(21, 1, 0), 39,
                encodeInstruction(21, 1, 0), 40
        ), program)
        assertContentEquals(arrayOf(
                "       0: write r0, 1",
                "       2: write r0, 2",
                "       4: write r0, 4"), ApfJniUtils.disassembleApf(program))

        gen = ApfGenerator(ApfGenerator.MIN_APF_VERSION_IN_DEV)
        gen.addDataCopy(1, 5)
        gen.addPacketCopy(1000, 255)
        program = gen.generate()
        assertContentEquals(byteArrayOf(
                encodeInstruction(25, 1, 1), 1, 5,
                encodeInstruction(25, 2, 0),
                0x03.toByte(), 0xe8.toByte(), 0xff.toByte(),
        ), program)
        assertContentEquals(arrayOf(
                "       0: dcopy 1, 5",
                "       3: pcopy 1000, 255"), ApfJniUtils.disassembleApf(program))

        gen = ApfGenerator(ApfGenerator.MIN_APF_VERSION_IN_DEV)
        gen.addDataCopy(ApfGenerator.Register.R1, 0, 5)
        gen.addPacketCopy(ApfGenerator.Register.R0, 1000, 255)
        program = gen.generate()
        assertContentEquals(byteArrayOf(
                encodeInstruction(21, 1, 1), 42, 0, 5,
                encodeInstruction(21, 2, 0),
                0, 41, 0x03.toByte(), 0xe8.toByte(), 0xff.toByte()
        ), program)
        assertContentEquals(arrayOf(
                "       0: dcopy [r1+0], 5",
                "       4: pcopy [r0+1000], 255"), ApfJniUtils.disassembleApf(program))
    }

    private fun encodeInstruction(opcode: Int, immLength: Int, register: Int): Byte {
        val immLengthEncoding = if (immLength == 4) 3 else immLength
        return opcode.shl(3).or(immLengthEncoding.shl(1)).or(register).toByte()
    }
}

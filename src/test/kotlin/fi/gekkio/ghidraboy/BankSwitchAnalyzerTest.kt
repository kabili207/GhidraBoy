// Copyright 2019-2020 Joonas Javanainen <joonas.javanainen@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package fi.gekkio.ghidraboy

import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class BankSwitchAnalyzerTest : IntegrationTest() {
    private lateinit var program: Program

    // ld a,0x02 / ld (0x2000),a — selects bank 2 for whatever flow follows
    private val selectBank2 = byteArrayOf(0x3e, 0x02, 0xea.toByte(), 0x00, 0x20)

    @BeforeEach
    fun beforeEach() {
        program = ProgramDB("test", language, language.defaultCompilerSpec, object {})
    }

    private fun bankAddress(
        bank: Int,
        offset: Long,
    ): Address = program.addressFactory.getAddressSpace("rom$bank").getAddress(offset)

    /** Disassembles from [entry], makes it a function, and runs the analyzer over it. */
    private fun analyzeFunctionAt(entry: Address) {
        program.withTransaction {
            val disassembler = Disassembler.getDisassembler(program, TaskMonitor.DUMMY, null)
            val disassembled = disassembler.disassemble(entry, null)
            program.functionManager.createFunction(null, entry, disassembled, SourceType.ANALYSIS)
            GameBoyBankSwitchAnalyzer().added(program, AddressSet(entry, entry), TaskMonitor.DUMMY, MessageLog())
        }
    }

    /** Name of the address space the flow reference out of [from] lands in. */
    private fun flowTargetSpace(from: Address): String =
        program.referenceManager
            .getReferencesFrom(from)
            .single { it.referenceType.isFlow }
            .toAddress.addressSpace.name

    /** True if any reference out of [from] lands on [to]. */
    private fun hasReferenceTo(
        from: Address,
        to: Address,
    ): Boolean = program.referenceManager.getReferencesFrom(from).any { it.toAddress == to }

    @Test
    fun `a far call through a jp hl helper resolves bank and target`() {
        program.withTransaction {
            // 0x0000 FarCall: ld (0x2000),a / jp hl   — switches to A, jumps to HL
            // 0x0010 caller:  ld a,2 / ld hl,0x4008 / call 0x0000
            program.memory.loadBytes(
                "rom0",
                address(0x0000),
                byteArrayOf(0xea.toByte(), 0x00, 0x20, 0xe9.toByte()) + ByteArray(0x0c) +
                    byteArrayOf(0x3e, 0x02, 0x21, 0x08, 0x40, 0xcd.toByte(), 0x00, 0x00),
            )
            program.memory.loadBytes("rom1", address(0x4000), ByteArray(0x10), overlay = true)
            program.memory.loadBytes("rom2", address(0x4000), ByteArray(0x10), overlay = true)
        }
        program.withTransaction {
            Disassembler.getDisassembler(program, TaskMonitor.DUMMY, null).disassemble(address(0x0000), null)
        }
        analyzeFunctionAt(address(0x0010))

        // The call still goes to the helper, and the far target it will reach is recorded too.
        assertTrue(hasReferenceTo(address(0x0015), address(0x0000))) { "lost the call to the helper" }
        assertTrue(hasReferenceTo(address(0x0015), bankAddress(2, 0x4008))) { "far target not resolved" }
    }

    @Test
    fun `a relative jump inside a bank stays in that bank`() {
        program.withTransaction {
            // ld a,2 / ld (0x2000),a / jr +1 / nop / ret
            program.memory.loadBytes(
                "rom1",
                address(0x4000),
                selectBank2 + byteArrayOf(0x18, 0x01, 0x00, 0xc9.toByte()),
                overlay = true,
            )
            program.memory.loadBytes("rom2", address(0x4000), ByteArray(0x10), overlay = true)
        }
        analyzeFunctionAt(bankAddress(1, 0x4000))

        // JR is PC-relative, so its target is in the same physical bank no matter what
        // the bank-select register was last set to.
        assertEquals("rom1", flowTargetSpace(bankAddress(1, 0x4005)))
    }

    @Test
    fun `a call through a bank-select helper selects the bank`() {
        program.withTransaction {
            // 0x0000 Bankswitch: ld (0x2000),a / ret   — the shape real games use
            // 0x0010 caller:     ld a,2 / call 0x0000 / call 0x4008
            val bankswitch = byteArrayOf(0xea.toByte(), 0x00, 0x20, 0xc9.toByte())
            program.memory.loadBytes(
                "rom0",
                address(0x0000),
                bankswitch + ByteArray(0x0c) +
                    byteArrayOf(0x3e, 0x02, 0xcd.toByte(), 0x00, 0x00, 0xcd.toByte(), 0x08, 0x40),
            )
            program.memory.loadBytes("rom1", address(0x4000), ByteArray(0x10), overlay = true)
            program.memory.loadBytes("rom2", address(0x4000), ByteArray(0x10), overlay = true)
        }
        // The helper has to be a function before a call to it can be recognised.
        program.withTransaction {
            val body =
                Disassembler
                    .getDisassembler(program, TaskMonitor.DUMMY, null)
                    .disassemble(address(0x0000), null)
            program.functionManager.createFunction(null, address(0x0000), body, SourceType.ANALYSIS)
        }
        analyzeFunctionAt(address(0x0010))

        assertEquals("rom2", flowTargetSpace(address(0x0015)))
    }

    @Test
    fun `a fixed-bank trampoline jumps into the selected bank`() {
        program.withTransaction {
            // ld a,2 / ld (0x2000),a / jp 0x4008
            program.memory.loadBytes("rom0", address(0x0000), selectBank2 + byteArrayOf(0xc3.toByte(), 0x08, 0x40))
            program.memory.loadBytes("rom1", address(0x4000), ByteArray(0x10), overlay = true)
            program.memory.loadBytes("rom2", address(0x4000), ByteArray(0x10), overlay = true)
        }
        analyzeFunctionAt(address(0x0000))

        assertEquals("rom2", flowTargetSpace(address(0x0005)))
    }
}

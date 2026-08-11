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
import ghidra.program.model.listing.Program
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class HardwareBlockTest : IntegrationTest() {
    private fun programWithHardwareBlocks(kind: GameBoyKind): Program {
        val program = ProgramDB("test", language, language.defaultCompilerSpec, object {})
        program.withTransaction {
            GameBoyUtils.addHardwareBlocks(program, kind, MessageLog())
        }
        return program
    }

    private fun assertOverlay(
        program: Program,
        name: String,
        overlay: Boolean,
    ) {
        val block = program.memory.getBlock(name)
        assertNotNull(block) { "No memory block named $name" }
        if (overlay) {
            assertTrue(block.isOverlay) { "$name should be an overlay" }
        } else {
            assertFalse(block.isOverlay) { "$name should be in the default address space" }
        }
    }

    @Test
    fun `CGB banked RAM is reachable in the default address space`() {
        val program = programWithHardwareBlocks(GameBoyKind.CGB)

        // A reference like LD A,(0xd0ad) resolves to the default space, so a global there
        // is only typeable if that space has a block behind it.
        assertTrue(program.memory.contains(address(0xd0ad))) { "wram bank 1 is unreachable at d0ad" }
        assertTrue(program.memory.contains(address(0x8000))) { "vram bank 0 is unreachable at 8000" }
    }

    @Test
    fun `CGB maps the boot-time bank normally and the rest as overlays`() {
        val program = programWithHardwareBlocks(GameBoyKind.CGB)

        assertOverlay(program, "vram0", overlay = false)
        assertOverlay(program, "vram1", overlay = true)
        assertOverlay(program, "wram0", overlay = false)
        assertOverlay(program, "wram1", overlay = false)
        for (bank in 2..7) {
            assertOverlay(program, "wram$bank", overlay = true)
        }
    }

    @Test
    fun `DMG has no banked RAM overlays`() {
        val program = programWithHardwareBlocks(GameBoyKind.GB)

        assertOverlay(program, "vram", overlay = false)
        assertOverlay(program, "wram", overlay = false)
        assertTrue(program.memory.contains(address(0xd0ad))) { "wram is unreachable at d0ad" }
    }
}

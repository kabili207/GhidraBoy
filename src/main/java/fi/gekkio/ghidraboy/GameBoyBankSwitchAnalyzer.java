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
package fi.gekkio.ghidraboy;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Resolves bankswitched calls and jumps into the right ROM overlay.
 *
 * <p>The SM83 only addresses 16 bits, so the loader maps each switchable ROM
 * bank as its own overlay over the 0x4000-0x7fff window (rom1, rom2, ...). A
 * {@code call $4d4b} therefore carries no bank: which physical bank it lands in
 * depends on the last value written to the MBC ROM bank-select register
 * (0x2000-0x3fff). Ghidra's stock analysis can't follow that, so banked code is
 * never disassembled and the only reachable code is the fixed bank.
 *
 * <p>This analyzer runs constant propagation per function and, at each flow
 * into the 0x4000-0x7fff window, picks the destination bank from:
 * <ol>
 *   <li>the constant most recently written to the bank-select register on this
 *       path (the {@code ld a,#bank; ld ($2000),a; call $4xxx} idiom), or</li>
 *   <li>failing that, the bank of the instruction's own overlay.</li>
 * </ol>
 * It then rewrites the flow reference to the overlay address and forces
 * disassembly (and, for calls, function creation) there. Newly revealed bank
 * code re-triggers analysis, so resolution converges without an explicit loop.
 *
 * <p>Known limits: bank state is tracked along the propagator's walk, not fully
 * per-path, so a bank set on one branch and consumed at a join can mis-resolve;
 * the intra-bank default is the safety net. Trampoline far-call helpers that
 * take the bank in a register or as inline bytes after the call are not handled
 * here. MBC5 banks above 255 (the 0x3000-0x3fff high bit) and MBC1's upper-bit
 * register at 0x4000-0x5fff are not modeled.
 */
public class GameBoyBankSwitchAnalyzer extends AbstractAnalyzer {
    private static final String NAME = "Game Boy bank switching";
    private static final String DESCRIPTION =
            "Resolves bankswitched calls/jumps into the correct ROM overlay and forces "
                    + "disassembly of the banked code they reach.";

    private static final String PROCESSOR_NAME = "SM83";

    // ROM bank-select register window. A constant store here selects the bank
    // visible at SWITCHED_LOW..SWITCHED_HIGH. Same range for MBC1/2/3/5.
    private static final long BANK_SEL_LOW = 0x2000L;
    private static final long BANK_SEL_HIGH = 0x3fffL;

    private static final long SWITCHED_LOW = 0x4000L;
    private static final long SWITCHED_HIGH = 0x7fffL;

    public GameBoyBankSwitchAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
        // Run after functions are created so propagation has real code to walk,
        // and so the functions we create re-enter this analyzer.
        setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        return PROCESSOR_NAME.equals(program.getLanguage().getProcessor().toString());
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        // No switchable banks => nothing to resolve. The loader names the first
        // overlay "rom1"; its absence means a non-banked (<=32 KiB) ROM.
        if (program.getAddressFactory().getAddressSpace("rom1") == null) {
            return true;
        }

        var symEval = new SymbolicPropogator(program);
        var regA = program.getRegister("A");
        var funcs = program.getFunctionManager().getFunctions(set, true);
        while (funcs.hasNext()) {
            monitor.checkCancelled();
            Function fn = funcs.next();
            var eval = new BankEvaluator(program, regA);
            try {
                symEval.flowConstants(fn.getEntryPoint(), fn.getBody(), eval, false, monitor);
            } catch (CancelledException e) {
                throw e;
            } catch (Exception e) {
                log.appendException(e);
            }
        }
        return true;
    }

    /**
     * Tracks the selected bank along the propagation walk and rewrites flows
     * into the switched window. One instance per function, so bank state does
     * not leak between functions.
     */
    private static final class BankEvaluator extends ContextEvaluatorAdapter {
        private final Program program;
        private final Register regA;
        private final ReferenceManager refMgr;
        private final AutoAnalysisManager mgr;

        // Constant last written to the bank-select register on this path, or -1
        // if unknown / not a constant.
        private long pendingBank = -1;

        BankEvaluator(Program program, Register regA) {
            this.program = program;
            this.regA = regA;
            this.refMgr = program.getReferenceManager();
            this.mgr = AutoAnalysisManager.getAnalysisManager(program);
        }

        @Override
        public boolean evaluateContext(VarnodeContext context, Instruction instr) {
            updateBank(context, instr);
            resolveFlow(instr);
            return false; // keep following flow
        }

        private void updateBank(VarnodeContext context, Instruction instr) {
            for (PcodeOp op : instr.getPcode()) {
                if (op.getOpcode() != PcodeOp.STORE) {
                    continue;
                }
                Long dst = context.getConstant(op.getInput(1), this);
                if (dst == null || dst < BANK_SEL_LOW || dst > BANK_SEL_HIGH) {
                    continue;
                }
                Long val = context.getConstant(op.getInput(2), this);
                pendingBank = (val != null) ? (val & 0x1ff) : -1;
            }
        }

        private void resolveFlow(Instruction instr) {
            FlowType ft = instr.getFlowType();
            boolean call = ft.isCall();
            boolean jump = ft.isJump();
            if (!call && !jump) {
                return;
            }
            Long target = directFlowTarget(instr);
            if (target == null || target < SWITCHED_LOW || target > SWITCHED_HIGH) {
                return;
            }

            long bank = pendingBank >= 1 ? pendingBank : bankOfSpace(instr.getAddress().getAddressSpace());
            if (bank < 1) {
                return; // fixed-bank flow with no known bank => ambiguous, leave it
            }
            AddressSpace overlay = program.getAddressFactory().getAddressSpace("rom" + bank);
            if (overlay == null) {
                return; // selected bank isn't loaded
            }
            Address to = overlay.getAddress(target);

            // If a flow reference already lands exactly there, we're done.
            // Otherwise drop the stale same-offset flow ref (wrong space) and
            // replace it with one into the resolved overlay.
            int opIndex = -1;
            for (Reference r : refMgr.getReferencesFrom(instr.getAddress())) {
                if (!r.getReferenceType().isFlow()) {
                    continue;
                }
                if (r.getToAddress().equals(to)) {
                    return;
                }
                if (r.getToAddress().getOffset() == target) {
                    opIndex = r.getOperandIndex();
                    refMgr.delete(r);
                }
            }
            if (opIndex < 0) {
                opIndex = operandIndexFor(instr, target);
            }

            RefType rt = call
                    ? (ft.isConditional() ? RefType.CONDITIONAL_CALL : RefType.UNCONDITIONAL_CALL)
                    : (ft.isConditional() ? RefType.CONDITIONAL_JUMP : RefType.UNCONDITIONAL_JUMP);
            Reference ref = refMgr.addMemoryReference(instr.getAddress(), to, rt, SourceType.ANALYSIS, opIndex);
            refMgr.setPrimary(ref, true);

            mgr.disassemble(to);
            if (call) {
                mgr.createFunction(to, false);
            }
        }

        /** The constant 16-bit destination of a direct call/jump, or null. */
        private static Long directFlowTarget(Instruction instr) {
            for (PcodeOp op : instr.getPcode()) {
                int oc = op.getOpcode();
                if (oc == PcodeOp.CALL || oc == PcodeOp.BRANCH || oc == PcodeOp.CBRANCH) {
                    Varnode d = op.getInput(0);
                    if (d != null && d.isAddress()) {
                        return d.getAddress().getOffset();
                    }
                }
            }
            return null;
        }

        /** Operand index holding {@code target}, falling back to the last operand. */
        private static int operandIndexFor(Instruction instr, long target) {
            for (int i = 0; i < instr.getNumOperands(); i++) {
                for (Object o : instr.getOpObjects(i)) {
                    if (o instanceof Address a && a.getOffset() == target) {
                        return i;
                    }
                    if (o instanceof Scalar s && s.getUnsignedValue() == target) {
                        return i;
                    }
                }
            }
            return Math.max(0, instr.getNumOperands() - 1);
        }

        /** Bank number encoded in an overlay space name ("rom28" -> 28), or -1. */
        private static long bankOfSpace(AddressSpace space) {
            String n = space.getName();
            if (n.length() > 3 && n.startsWith("rom")) {
                try {
                    return Long.parseLong(n.substring(3));
                } catch (NumberFormatException ignored) {
                    // not a rom<N> overlay
                }
            }
            return -1;
        }
    }
}

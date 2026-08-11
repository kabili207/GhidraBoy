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
import ghidra.program.model.listing.CodeUnit;
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

import java.util.HashMap;
import java.util.Map;

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
 *   <li>the bank of the instruction's own overlay, when the flow comes from
 *       banked code, or</li>
 *   <li>the constant most recently written to the bank-select register on this
 *       path, either inline ({@code ld a,#bank; ld ($2000),a; call $4xxx}) or by
 *       calling a helper that writes the register from A. The helper form is what
 *       real games use, since the write has to run from the fixed bank:
 *       {@code ld a,BANK(target); call Bankswitch; call target}.</li>
 * </ol>
 * It then rewrites the flow reference to the overlay address and forces
 * disassembly (and, for calls, function creation) there. Newly revealed bank
 * code re-triggers analysis, so resolution converges without an explicit loop.
 *
 * <p>Known limits: bank state is tracked along the propagator's walk, not fully
 * per-path, so in a fixed-bank function a bank set on one branch and consumed at
 * a join can mis-resolve. Flows from inside a bank are unaffected, since they
 * always resolve to their own bank. Far-call helpers that jump to a target held
 * in a register ({@code jp hl}) or read the bank and target from inline bytes
 * after the call are not resolved, and neither are data-driven jump tables: use
 * Ghidra's undefined-code search to find what those reach. MBC5 banks above 255
 * (the 0x3000-0x3fff high bit) and MBC1's upper-bit register at 0x4000-0x5fff
 * are not modeled.
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

    // Bounds on the helper scan. Big enough for a chained far-call helper (rst -> jp body ->
    // call the jp-hl routine), small enough that an ordinary function isn't classified as one.
    private static final int HELPER_SCAN_BUDGET = 24;
    private static final int HELPER_MAX_DEPTH = 2;

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
        var regHl = program.getRegister("HL");
        // Rebuilt per run: functions created since the last pass may be helpers.
        var helpers = new HashMap<Address, BankEvaluator.HelperInfo>();
        var funcs = program.getFunctionManager().getFunctions(set, true);
        while (funcs.hasNext()) {
            monitor.checkCancelled();
            Function fn = funcs.next();
            var eval = new BankEvaluator(program, regA, regHl, helpers);
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
        private final Register regHl;
        private final ReferenceManager refMgr;
        private final AutoAnalysisManager mgr;
        private final Map<Address, HelperInfo> helpers;

        // Constant last written to the bank-select register on this path, or -1
        // if unknown / not a constant.
        private long pendingBank = -1;

        BankEvaluator(Program program, Register regA, Register regHl, Map<Address, HelperInfo> helpers) {
            this.program = program;
            this.regA = regA;
            this.regHl = regHl;
            this.helpers = helpers;
            this.refMgr = program.getReferenceManager();
            this.mgr = AutoAnalysisManager.getAnalysisManager(program);
        }

        @Override
        public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {
            // Read A and HL before the call, since the call itself clobbers them.
            resolveHelperCall(context, instr);
            return false;
        }

        @Override
        public boolean evaluateContext(VarnodeContext context, Instruction instr) {
            updateBank(context, instr);
            resolveComputedJump(context, instr);
            resolveFlow(instr);
            return false; // keep following flow
        }

        /**
         * Games rarely write the bank register inline: the write has to run from the fixed
         * bank, so it lives in a shared helper. Two shapes matter, and a helper can be both:
         * one takes the bank in A and returns ({@code ld a,BANK / call Bankswitch / call x}),
         * the other also takes the target in HL and jumps to it ({@code ld a,BANK / ld hl,x /
         * rst FarCall}). Either way the constants live at the call site, so that is where they
         * have to be read.
         */
        private void resolveHelperCall(VarnodeContext context, Instruction instr) {
            if (!instr.getFlowType().isCall()) {
                return;
            }
            for (Address entry : instr.getFlows()) {
                if (entry.getAddressSpace().isOverlaySpace()) {
                    continue;
                }
                HelperInfo helper = classifyHelper(entry);
                if (!helper.selectsBank() && !helper.jumpsToHl()) {
                    continue;
                }
                Long bank = helper.selectsBank() ? constantOfRegister(context, regA) : null;
                if (helper.selectsBank()) {
                    pendingBank = (bank != null) ? (bank & 0x1ff) : -1;
                }
                if (helper.jumpsToHl()) {
                    Long target = constantOfRegister(context, regHl);
                    if (target != null) {
                        resolveFarCall(instr, target, bank);
                    }
                }
                return;
            }
        }

        /**
         * What calling the routine at {@code entry} does to bank state and control flow.
         *
         * <p>The walk follows fall-through, unconditional jumps and direct calls, because real
         * helpers are chained: pokecrystal's FarCall is {@code rst $08 -> jp 2d63 -> ... ->
         * call 2d82}, and only that last routine is the {@code jp hl}. It is bounded by an
         * instruction budget and a call depth so a large routine can't be mistaken for a
         * helper. HL clobbering is tracked because a helper that rewrites HL before jumping is
         * not jumping to the caller's value, so the caller's HL means nothing.
         */
        private HelperInfo classifyHelper(Address entry) {
            HelperInfo cached = helpers.get(entry);
            if (cached != null) {
                return cached;
            }
            helpers.put(entry, HelperInfo.NONE); // breaks recursion through mutually-calling helpers
            var scan = new HelperScan();
            scan.walk(entry, 0);
            var info = new HelperInfo(scan.selectsBank, scan.jumpsToHl);
            helpers.put(entry, info);
            return info;
        }

        private final class HelperScan {
            private boolean selectsBank;
            private boolean jumpsToHl;
            private boolean hlClobbered;
            private int budget = HELPER_SCAN_BUDGET;

            private void walk(Address entry, int depth) {
                Instruction instr = program.getListing().getInstructionAt(entry);
                while (instr != null && budget > 0) {
                    budget--;
                    if (writesBankSelectFromA(instr)) {
                        selectsBank = true;
                    }
                    FlowType ft = instr.getFlowType();
                    if (ft.isJump() && ft.isComputed()) {
                        jumpsToHl = !hlClobbered;
                        return;
                    }
                    if (clobbersHl(instr)) {
                        hlClobbered = true;
                    }
                    if (ft.isTerminal()) {
                        return;
                    }
                    if (ft.isCall()) {
                        if (depth < HELPER_MAX_DEPTH) {
                            for (Address callee : instr.getFlows()) {
                                if (!callee.getAddressSpace().isOverlaySpace()) {
                                    walk(callee, depth + 1);
                                }
                            }
                        }
                        if (jumpsToHl) {
                            return;
                        }
                    } else if (ft.isJump() && !ft.isConditional()) {
                        Address[] flows = instr.getFlows();
                        if (flows.length != 1) {
                            return;
                        }
                        instr = program.getListing().getInstructionAt(flows[0]);
                        continue;
                    }
                    instr = instr.getNext();
                }
            }
        }

        private boolean clobbersHl(Instruction instr) {
            for (Object result : instr.getResultObjects()) {
                if (result instanceof Register reg && (regHl.contains(reg) || reg.contains(regHl))) {
                    return true;
                }
            }
            return false;
        }

        /** Constant a register holds at this point, or null if propagation doesn't know. */
        private Long constantOfRegister(VarnodeContext context, Register reg) {
            Varnode value = context.getRegisterVarnodeValue(reg);
            return (value != null) ? context.getConstant(value, this) : null;
        }

        /** {@code jp hl} where propagation pinned HL down: the destination is knowable. */
        private void resolveComputedJump(VarnodeContext context, Instruction instr) {
            FlowType ft = instr.getFlowType();
            if (!ft.isJump() || !ft.isComputed()) {
                return;
            }
            Long target = constantOfRegister(context, regHl);
            if (target != null) {
                recordTarget(instr, target, null, RefType.COMPUTED_JUMP);
            }
        }

        /**
         * Records the far call the helper will perform. The helper does the bank switch itself
         * from the fixed bank, so unlike a direct flow this can legitimately leave the caller's
         * own bank, and {@code bank} (the helper's A argument) wins when it is known.
         */
        private void resolveFarCall(Instruction instr, long target, Long bank) {
            recordTarget(instr, target, bank, RefType.UNCONDITIONAL_CALL);
        }

        private void recordTarget(Instruction instr, long target, Long bank, RefType type) {
            Address to;
            if (target >= SWITCHED_LOW && target <= SWITCHED_HIGH) {
                long selected = bank != null ? bank : effectiveBank(instr);
                if (selected < 1) {
                    return;
                }
                AddressSpace overlay = program.getAddressFactory().getAddressSpace("rom" + selected);
                if (overlay == null) {
                    return;
                }
                to = overlay.getAddress(target);
            } else if (target < SWITCHED_LOW) {
                to = program.getAddressFactory().getDefaultAddressSpace().getAddress(target);
            } else {
                return; // a RAM target isn't code we can attribute to a bank
            }

            for (Reference r : refMgr.getReferencesFrom(instr.getAddress())) {
                if (r.getToAddress().equals(to)) {
                    return;
                }
            }
            // Attached to the mnemonic, not the operand: for a helper call the real flow goes
            // to the helper, and that reference has to stay primary.
            refMgr.addMemoryReference(instr.getAddress(), to, type, SourceType.ANALYSIS, CodeUnit.MNEMONIC);
            mgr.disassemble(to);
            if (type.isCall()) {
                mgr.createFunction(to, false);
            }
        }

        /** Bank a direct flow from this instruction lands in, or -1 when unknown. */
        private long effectiveBank(Instruction instr) {
            long ownBank = bankOfSpace(instr.getAddress().getAddressSpace());
            return ownBank >= 1 ? ownBank : pendingBank;
        }

        private record HelperInfo(boolean selectsBank, boolean jumpsToHl) {
            static final HelperInfo NONE = new HelperInfo(false, false);
        }

        private boolean writesBankSelectFromA(Instruction instr) {
            for (PcodeOp op : instr.getPcode()) {
                if (op.getOpcode() != PcodeOp.COPY) {
                    continue;
                }
                Varnode out = op.getOutput();
                if (out == null || !out.getAddress().isMemoryAddress() || !isBankSelect(out.getOffset())) {
                    continue;
                }
                Varnode in = op.getInput(0);
                if (in != null && in.isRegister() && in.getAddress().equals(regA.getAddress())) {
                    return true;
                }
            }
            return false;
        }

        private void updateBank(VarnodeContext context, Instruction instr) {
            for (PcodeOp op : instr.getPcode()) {
                Varnode value;
                if (op.getOpcode() == PcodeOp.STORE) {
                    // ld (hl),a and friends, where the address is only known by propagation.
                    Long dst = constantOf(context, op.getInput(1));
                    if (dst == null || !isBankSelect(dst)) {
                        continue;
                    }
                    value = op.getInput(2);
                } else if (op.getOpcode() == PcodeOp.COPY) {
                    // ld (0x2000),a — the usual idiom. Sleigh resolves the constant address at
                    // compile time, so this is a copy into a ram varnode and never a STORE.
                    Varnode out = op.getOutput();
                    if (out == null || !out.getAddress().isMemoryAddress() || !isBankSelect(out.getOffset())) {
                        continue;
                    }
                    value = op.getInput(0);
                } else {
                    continue;
                }
                Long bank = constantOf(context, value);
                pendingBank = (bank != null) ? (bank & 0x1ff) : -1;
            }
        }

        /**
         * Propagated constant behind a varnode, or null if it isn't known. Registers have to
         * be resolved through {@code getValue} first: {@code getConstant} alone returns null
         * for a register varnode even when propagation knows exactly what it holds.
         */
        private Long constantOf(VarnodeContext context, Varnode vn) {
            Varnode value = context.getValue(vn, this);
            return (value != null) ? context.getConstant(value, this) : null;
        }

        private static boolean isBankSelect(long address) {
            return address >= BANK_SEL_LOW && address <= BANK_SEL_HIGH;
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

            // Code in a switched bank can't select its own bank, since the write swaps the
            // code out from under the PC. So a direct flow from bank code stays in that bank,
            // and only a fixed-bank trampoline's flow follows the pending bank select.
            long ownBank = bankOfSpace(instr.getAddress().getAddressSpace());
            long bank = ownBank >= 1 ? ownBank : pendingBank;
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

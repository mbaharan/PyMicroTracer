"""
        Author: Mohammadreza Baharani
        Email: mbaharan@uncc.edu
        University of North Carolina at Charlotte
        Date:          Dec 1, 2017-10:24:04 AM
        Arguments:
            machineMode: This is the mode of architecture
            machineArch: The architecture of CPU, 
            PC: Program Counter, Default is 0,
            op= instruction, 
            datail: Should I save everything = True, Defualt is False,
            debug: Should I print everything
        Outputs:      -
        Dependencies: 
"""

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CsError, CS_MODE_ARM, CS_ARCH_ARM, CS_MODE_V8
from capstone.arm_const import ARM_REG_PC
import PyMicroTracer.Constant as cnst


class Instruction:
    def __init__(self, machine_mode, machine_arch, log_handler, ip=0, op='', bll_id=-1, save_detail=False,
                 log_output=False, cycle_needed=1):

        self.machineArch = machine_arch
        self.machineMode = machine_mode
        self.machine = 0
        self.ip = ip
        self.op = op
        self.disAssembledInstruction = 0
        self.readRegisters = ()
        self.writeRegisters = ()
        self.isItRestoreFromFile = False
        self.perCycle = cycle_needed
        self.BBid = bll_id
        self.saveDetail = save_detail
        self.stringOfInstruction = 'Not disassembled!'
        self.dictionaryForRegisters = dict()
        self.log_handler = log_handler
        self.log_output = log_output

    def dis_assemble(self):

        status = cnst.fail()

        try:
            """
                Also it is possible to disassemble the whole code, but here only I get one. 
            """
            machine = Cs(self.machineArch, self.machineMode)
            machine.detail = True
            for inst in machine.disasm(bytes(bytearray.fromhex(self.op)), self.ip):

                if self.saveDetail:
                    self.disAssembledInstruction = inst
                    self.machine = machine

                self.extract_registers(inst)
                status = cnst.success()
        except CsError as e:
            self.log_handler.error("%s" % e)

        return status

    def extract_registers(self, inst=None, consider_pc=False):
        status = cnst.fail()
        if inst is not None:
            (self.readRegisters, self.writeRegisters) = inst.regs_access()

            self.readRegisters = set(self.readRegisters)
            if self.machineArch == CS_ARCH_X86:
                self.readRegisters = set(self.readRegisters) - {34, 41}  # Remove IP, and RIP from registers
            elif self.machineArch == CS_ARCH_ARM and consider_pc:
                self.readRegisters = set(self.readRegisters) - {ARM_REG_PC} # Remove IP, and RIP from registers

            self.readRegisters = list(self.readRegisters)

            for reg in self.readRegisters:
                self.dictionaryForRegisters[reg] = inst.reg_name(reg)

            for reg in self.writeRegisters:
                self.dictionaryForRegisters[reg] = inst.reg_name(reg)

            self.stringOfInstruction = "<0x%x:\t%s\t%s>" % (self.ip, inst.mnemonic, inst.op_str)

            if self.log_output:
                self.log_handler.info("-> Instruction:\t%s\t%s" % (inst.mnemonic, inst.op_str))

                for reg in self.writeRegisters:
                    self.log_handler.info("\tModified Registers:\t%s" % (inst.reg_name(reg)))

                for reg in self.readRegisters:
                    self.log_handler.info("\tAccessed Registers:\t%s" % (inst.reg_name(reg)))

            status = cnst.success()

        return status

    def __str__(self):
        return self.stringOfInstruction

    def __repr__(self):
        return self.stringOfInstruction

    def to_str(self):
        return self.stringOfInstruction

    def __getstate__(self):
        # Copy the object's state from self.__dict__ which contains
        # all our instance attributes. Always use the dict.copy()
        # method to avoid modifying the original state.
        state = self.__dict__.copy()
        # Remove the unpicklable entries.
        if self.saveDetail:
            del state['msh']
            del state['disAssembledInstruction']
        return state

    def __setstate__(self, state):
        # Restore instance attributes (i.e., filename and lineno).
        self.__dict__.update(state)
        # Restore the previously opened file's state. To do so, we need to
        # reopen it and read from it until the line count is restored.
        if self.saveDetail:
            self.dis_assemble()


'''
    Function name: __main__ 
    Inputs: -
    Outputs: -
    Date added: Nov 29, 2017-11:34:22 AM
'''
if __name__ == "__main__":

    import logging

    def unit_testing(dut):
        print("-------------------------------------")
        print(dut)
        for reg in dut.readRegisters:
            print("\tRead-from Registers: {}, Reg_ID:{}".format(dut.dictionaryForRegisters[reg], reg))
        for reg in dut.writeRegisters:
            print("\tWritten-on Registers: {}, Reg_ID:{}".format(dut.dictionaryForRegisters[reg], reg))
        print("-------------------------------------")


    ops = ["eb93", "4989d1"] #x86 operations
    arm_ops=["00b0a0e3", "00e0a0e3", "04109de4"]
    m_m = CS_MODE_ARM + CS_MODE_V8
    m_a = CS_ARCH_ARM

    for op in arm_ops:
        design_under_test = Instruction(machine_mode=m_m, machine_arch=m_a, log_handler=logging,
                                        ip=1, op=op, log_output=True)
        design_under_test.dis_assemble()

        import dill

        with open('testIns.bb', 'wb') as f:
            dill.dump(design_under_test, f)

        unit_testing(design_under_test)

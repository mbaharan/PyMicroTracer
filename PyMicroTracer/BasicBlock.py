"""
        Project: PyDGP
        File name: BasicBlock
        Author: mbaharan -- Mohammadreza Baharani
        Email: 
        University of North Carolina at Charlotte
        Date:          Jan 12, 2018-4:03 PM
        Arguments:
        Outputs:
        Dependencies: 
"""

from PyMicroTracer.Instruction import Instruction
from PyMicroTracer.Dependency import Dependency
import PyMicroTracer.Constant as cnst

from capstone import CS_ARCH_X86, CS_MODE_64, CS_MODE_ARM, CS_ARCH_ARM, CS_MODE_V8
import HTML
import networkx as nx
from builtins import str


class BasicBlock:

    def __init__(self, operations, machine_mode, machine_arch, log_handler, bbl_id, prefix='./',
                 bbl_base_addr=0, log_output=False):
        '''
        Constructor
        '''
        self.ops = operations
        self.parsedInst = []
        self.machineMode = machine_mode
        self.machineArch = machine_arch
        self.log_output = log_output
        self.dependencyMatrix = []
        self.howManyParsedInst = 0
        self.dependencyGraph = 0
        self.howManyCalled = 1
        self.prefix = prefix
        self.bbID = bbl_id
        self.IPC = 0
        self.longestPath = ''
        self.readRegsAtBoarder = set([])
        self.writeRegsAtBoarder = set([])
        self.bbAddr = bbl_base_addr
        self.log_handler = log_handler
        self.log_output = log_output

    def called_again(self):
        self.howManyCalled = self.howManyCalled + 1

    def skim_instructions(self):
        for (pc, op) in self.ops:
            inst = Instruction(machine_mode=self.machineMode, machine_arch=self.machineArch,
                               log_handler=self.log_handler, ip=pc, op=op, log_output=self.log_output)
            if inst.dis_assemble() == cnst.success():
                self.parsedInst.append(inst)
                inst_to_string = str(inst)
                if self.log_output:
                    self.log_handler.info(inst_to_string)
            else:
                if self.log_output:
                    self.log_handler.warn("The instruction 0x%x can be not parsed!" % pc)

        self.howManyParsedInst = len(self.parsedInst)
        self.dependencyMatrix = [[[] for j in range(self.howManyParsedInst)] for i in range(self.howManyParsedInst)]

    def extract_dependency(self, opt=[cnst.dep_raw(), cnst.dep_war(), cnst.dep_waw()]):
        if cnst.dep_raw() in opt:
            self.extract_raw_dep()
        if cnst.dep_waw() in opt:
            self.extract_waw_dep()
        if cnst.dep_war in opt:
            self.extract_war_dep()

    def extract_raw_dep(self):
        row = self.howManyParsedInst - 1
        col = self.howManyParsedInst - 1
        for rowInst in reversed(self.parsedInst):
            tmp = rowInst.readRegisters
            if len(tmp) > 0:
                for colInst in reversed(self.parsedInst):
                    if rowInst.ip > colInst.ip:
                        for readReg in tmp:

                            if self.machineArch == CS_ARCH_X86:
                                all_family = cnst.is_it_shredded_register(readReg)
                            else:
                                if not isinstance(readReg, type([])):
                                    all_family = [readReg]

                            if len(all_family) > 0:
                                for member in all_family:
                                    if member in colInst.writeRegisters:
                                        dep = Dependency(rowInst.dictionaryForRegisters[readReg],
                                                         cnst.dep_raw())
                                        arr = self.dependencyMatrix[row][col]
                                        arr.append(dep)  # it acts like pointer in `C`
                                        tmp.remove(readReg)
                                        break
                            else:
                                if readReg in colInst.writeRegisters:
                                    dep = Dependency(rowInst.dictionaryForRegisters[readReg],
                                                     cnst.dep_raw())
                                    arr = self.dependencyMatrix[row][col]
                                    arr.append(dep)  # it acts like pointer in `C`
                                    tmp.remove(readReg)
                    col = col - 1
            col = self.howManyParsedInst - 1
            if len(tmp) > 0:
                for reg in tmp:
                    self.readRegsAtBoarder.add(reg)
            row = row - 1

    def extract_war_dep(self):
        row = self.howManyParsedInst - 1
        col = self.howManyParsedInst - 1
        for rowInst in reversed(self.parsedInst):
            tmp = rowInst.writeRegisters
            for colInst in reversed(self.parsedInst):
                if rowInst.ip > colInst.ip:
                    for Reg in tmp:
                        if Reg in colInst.readRegisters:
                            dep = Dependency(colInst.dictionaryForRegisters[Reg], cnst.dep_war())
                            arr = self.dependencyMatrix[row][col]
                            arr.append(dep)  # it acts like pointer in `C`
                            tmp.remove(Reg)
                col = col - 1
            col = self.howManyParsedInst - 1
            row = row - 1

    def extract_waw_dep(self):
        row = self.howManyParsedInst - 1
        col = self.howManyParsedInst - 1
        for rowInst in reversed(self.parsedInst):
            tmp = rowInst.writeRegisters
            for colInst in reversed(self.parsedInst):
                if rowInst.PC > colInst.PC:
                    for Reg in tmp:
                        if Reg in colInst.writeRegisters:
                            dep = Dependency(colInst.dictionaryForRegisters[Reg], cnst.dep_waw())
                            arr = self.dependencyMatrix[row][col]
                            arr.append(dep)  # it acts like pointer in `C`
                            tmp.remove(Reg)
                col = col - 1
            col = self.howManyParsedInst - 1
            row = row - 1

    def str_row_dependency(self, idx, ending='\n'):
        arr = []
        val = ""
        for col in self.dependencyMatrix[idx]:
            for dep in col:
                val = val + str(dep) + ending
            arr.append(val)
            val = ""
        return arr

    def draw_html_table(self):
        header = []
        header.append('Instructions')
        for ins in self.parsedInst:
            header.append("%s" % str(ins))
        row = []
        r_index = 0
        for ins in self.parsedInst:
            inst_text = ["%s" % str(ins)]
            row.append(inst_text + self.str_row_dependency(r_index, '<br/>'))
            r_index = r_index + 1
        row = [header] + row

        html_code = HTML.table(row, header)
        with open(self.prefix + "res.html", "w") as file:
            file.write(html_code)

    def extract_graph(self):

        def is_there_dependency(row):
            dep = False
            for col_inside in row:
                if len(col_inside) > 0:
                    dep = True
                    break
            return dep

        if self.dependencyMatrix:
            self.dependencyGraph = nx.DiGraph()
            for i in range(len(self.parsedInst)):
                self.dependencyGraph.add_node(i)

            row_idx = 0
            col_idx = 0
            for row in self.dependencyMatrix:
                if is_there_dependency(row):
                    for col in row:
                        if len(col) > 0:
                            self.dependencyGraph.add_edge(col_idx, row_idx)
                        col_idx = col_idx + 1
                row_idx = row_idx + 1
                col_idx = 0

    def export_graph_as_dot(self, save_as_pdf=False):
        if self.dependencyGraph:
            from networkx.drawing.nx_agraph import write_dot
            labels = {}
            i = 0
            for inst in self.parsedInst:
                labels[i] = "%s) %s" % (str(i), inst)
                i = i + 1

            renamed_graph = nx.relabel_nodes(self.dependencyGraph, labels)
            assert (renamed_graph.order() == self.howManyParsedInst)
            base_file_name = self.prefix + 'depthGraph_bb' + str(self.bbID) + ("_%x" % self.bbAddr)
            write_dot(renamed_graph, base_file_name + '.dot')

            import pydot
            (graph,) = pydot.graph_from_dot_file(base_file_name + '.dot')
            if save_as_pdf:
                graph.write_pdf(base_file_name + '.pdf')
        else:
            if self.log_output:
                self.log_handler.error("Cannot export graph as a PDF.")

    def extract_static_ipc(self):
        if nx.is_directed(self.dependencyGraph):
            lng_path = nx.dag_longest_path(self.dependencyGraph)
            if self.log_output:
                self.log_handler.info("Longest path:%s\n" % str(lng_path))
            self.longestPath = str(lng_path)
            self.IPC = float(self.dependencyGraph.order()) / len(lng_path)

    def alive_registers(self):
        if self.dependencyGraph != 0:
            for inst in self.parsedInst:
                for reg in inst.writeRegisters:
                    self.writeRegsAtBoarder.add(reg)


if __name__ == "__main__":

    import logging

    m_m = CS_MODE_ARM + CS_MODE_V8
    m_a = CS_ARCH_ARM

    ops = ((int("0x1044c", 16), "00b0a0e3"),
           (int("0x10450", 16), "00e0a0e3"),
           (int("0x10454", 16), "04109de4"),
           (int("0x10458", 16), "0d20a0e1"),
           (int("0x1045c", 16), "04202de501"),
           (int("0x10460", 16), "04002de501"),
           (int("0x10464", 16), "10c09fe5"),
           (int("0x10468", 16), "04c02de501"),
           (int("0x1046c", 16), "0c009fe5"),
           (int("0x10470", 16), "0c309fe5"))

    '''
    ops = (("0x00000000004022e0", "ff3522bd2100"),
       ("0x00000000004022e6" , "ff2524bd2100"),
       ("0x0000000000402790" , "ff25d2ba2100"),
       ("0x0000000000402790" , "ff25d2ba2100"),
       ("0x0000000000402340" , "ff25fabc2100"))
    '''
    pref = '/home/mbaharan/ArmOutput/'
    DUT = BasicBlock(operations=ops, machine_mode=m_m, machine_arch=m_a, bbl_id=0, log_handler=logging,
                     prefix=pref)
    DUT.skim_instructions()
    DUT.extract_dependency([cnst.dep_raw()])
    DUT.extract_graph()
    DUT.export_graph_as_dot(save_as_pdf=True)
    DUT.alive_registers()
    #print(DUT.dependencyMatrix)
    # DUT.printMatrixDependency()
    DUT.draw_html_table()
    # print("IPC: %.2f" % DUT.IPC())

    print("FINISHED")

from PyMicroTracer.SuperBasicBlock import SuperBasicBlock
from PyMicroTracer.Instruction import Instruction
import PyMicroTracer.Constant as cnst


class HybridBasicBlock(SuperBasicBlock):
    def __init__(self, db_file_name, start_from_bbl_id, machine_mode, machine_arch, log_handler,
                 instruction_scheduler_window_size=-1, prefix_dir='./', log_output=False):
        super().__init__(db_file_name=db_file_name, start_from_bbl_id=start_from_bbl_id, machine_mode=machine_mode,
                         machine_arch=machine_arch, log_handler=log_handler,
                         prefix_dir=prefix_dir, log_output=log_output)

        self.bbl_instr_indx = {}
        self._instruction_scheduler_window_size = instruction_scheduler_window_size

    def skim_instructions(self, data):
        count_local = 0
        idx = len(self.parsedInst)
        for row in reversed(data):
            op = row[3]
            pc = int(row[1], 16)
            bbl_id = int(row[0])
            inst = Instruction(machine_mode=self.machineMode, machine_arch=self.machineArch,
                               log_handler=self.log_handler, bll_id=bbl_id, ip=pc,
                               op=op, log_output=self.log_output)

            if inst.dis_assemble() == cnst.success():
                if len(inst.readRegisters) > 0 or len(inst.writeRegisters) > 0:
                    self.parsedInst.append(inst)

                    if bbl_id in self.bbl_instr_indx:
                        self.bbl_instr_indx[bbl_id].add(idx)
                    else:
                        self.bbl_instr_indx[bbl_id] = set()
                        self.bbl_instr_indx[bbl_id].add(idx)

                    idx = idx + 1

                    count_local = count_local + 1
                    if self.log_output:
                        self.log_handler.info(inst)
                else:
                    if self.log_output:
                        self.log_handler.debug("%s is useless!" % inst)
            else:
                self.log_handler.error("The instruction 0x%x can be not parsed!" % pc)
        return count_local

    def _extract_start_end_based_on_bbls(self, start, end):
        idx = set()

        for bbl_idx in range(start, end, -1):
            if bbl_idx in self.bbl_instr_indx:
                idx = idx | self.bbl_instr_indx[bbl_idx]
        if len(idx):
            return [min(idx), max(idx)]
        else:
            self.log_handler.error("For start:{} and end:{}, idx is empty")
            return [-1, -1]

    def extract_ipc_based_on_bbl(self, bbl_size_scheduler=-1, infinite_scheduler=False):
        from math import ceil
        from numpy import zeros

        max_scheduled_inst = -1
        if bbl_size_scheduler > 0:
            how_many_seg = ceil(self.how_many_basic_block_has_been_read / bbl_size_scheduler)

            window_size = -1

            if not infinite_scheduler:
                window_size = self._instruction_scheduler_window_size
                len_backend = len(window_size)
                ipc = zeros((how_many_seg, len_backend))
                val = zeros((len_backend, 1))

            for idx in range(0, int(how_many_seg)):
                start = self.start_from_bbl_id - bbl_size_scheduler*idx
                end = max(start - bbl_size_scheduler, self.last_bbl_id_has_been_read)

                if start > end:
                    [start_inst, end_inst] = self._extract_start_end_based_on_bbls(start, end)
                    if start_inst > -1:
                        local_data = self.parsedInst[start_inst: end_inst]
                        [hbb_ipc, max_scheduled_inst_loca] = self.extract_ipc_based_on_rob(window_size=window_size,
                                                                                           data_source=local_data,
                                                                                           save_output=False)

                        max_scheduled_inst = max(max_scheduled_inst, max_scheduled_inst_loca)
                        ipc[idx, :] = hbb_ipc

            for idx in range(0, len_backend):
                val[idx, 0] = sum(ipc[:, idx]) / how_many_seg

        return [val, max_scheduled_inst]

    def extract_ipc_based_on_rob(self, window_size=-1, data_source=None, save_output=False):
        max_parallel_inst = -1

        if data_source is None:
            data_source = self.parsedInst

        total = len(data_source)

        data_portion = data_source
        dependency_matrix = self.extract_raw_dep(data_portion=data_portion)
        dependency_graph = self.extract_graph(dependency_matrix=dependency_matrix)
        [level_local, max_local] = self.find_levels(dependency_graph)
        max_parallel_inst = max(max_local, max_parallel_inst)

        avg_ipc = self._cal_ipc(instruction_scheduler_window_sizes=window_size, levels=level_local, total_inst=total)

        if save_output:
            suffix_name = "%d_%s" % (window_size, 'all')
            self.draw_html_table(data_portion=data_portion, dependency_matrix=dependency_matrix,
                                 suffix_name=suffix_name)
            self.export_graph_as_dot(data_portion=data_portion, dependency_graph=dependency_graph,
                                     suffix_name=suffix_name)

        return [avg_ipc, max_parallel_inst]

    def _cal_ipc(self, instruction_scheduler_window_sizes, levels, total_inst):

        vals = list()
        from math import ceil
        cycles = 0

        for backend_instruction_windows_size in instruction_scheduler_window_sizes:
            print("Backed-end instruction scheduler windows size:{}".format(backend_instruction_windows_size))
            self.log_handler.info("Backed-end instruction scheduler windows size:{}".format(backend_instruction_windows_size))

            for level in levels:
                cycles = cycles + max(ceil(len(level)/backend_instruction_windows_size), 1)
            vals.append(total_inst / cycles)

        return vals
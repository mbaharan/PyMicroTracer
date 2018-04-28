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

    def extract_ipc_based_on_bbl(self, bbl_size_scheduler=-1, infinite_scheduler=False, last_levels_hybtid=None):
        from math import ceil
        from numpy import zeros

        max_scheduled_inst = -1


        if bbl_size_scheduler > 0:
            if last_levels_hybtid is not None:
                how_many_seg = len(last_levels_hybtid)
            else:
                how_many_seg = ceil(self.how_many_basic_block_has_been_read / bbl_size_scheduler)

            future_levels_hybrid = []

            window_size = []

            if not infinite_scheduler:
                window_size = self._instruction_scheduler_window_size

                len_backend = len(window_size)

                seg_ins_clk = zeros((how_many_seg, len_backend, 2))
                val = zeros((len_backend, 1))

            for idx in range(0, int(how_many_seg)):

                if last_levels_hybtid is None:

                    start = self.start_from_bbl_id - bbl_size_scheduler*idx
                    end = max(start - bbl_size_scheduler, self.last_bbl_id_has_been_read)

                    if start > end:
                        [start_inst, end_inst] = self._extract_start_end_based_on_bbls(start, end)
                        if start_inst > -1:
                            local_data = self.parsedInst[start_inst: end_inst]
                        last_level_local = None

                else:
                        last_level_local = last_levels_hybtid[idx]
                        local_data= None

                [ins_clks, max_scheduled_inst_loca, future_level_local] = self.hybrid_extract_ipc_based_on_rob(
                    window_size=window_size,
                    data_source=local_data,
                    save_output=False,
                    last_level=last_level_local)

                if last_levels_hybtid is None:
                    future_levels_hybrid.append(future_level_local)

                inst_sched_idx = 0
                for ins_clk in ins_clks:
                    seg_ins_clk[idx][inst_sched_idx][1] = seg_ins_clk[idx][inst_sched_idx][1] + ins_clk[1]
                    seg_ins_clk[idx][inst_sched_idx][0] = seg_ins_clk[idx][inst_sched_idx][0] + ins_clk[0]
                    inst_sched_idx = inst_sched_idx + 1

                max_scheduled_inst = max(max_scheduled_inst, max_scheduled_inst_loca)

            for idx_inst_wid in range(0, len_backend):
                inst = sum(seg_ins_clk[:, idx_inst_wid, 0])
                cyc = sum(seg_ins_clk[:, idx_inst_wid, 1])
                val[idx_inst_wid, 0] = inst / cyc

        return [val, max_scheduled_inst, future_levels_hybrid]


    def hybrid_extract_ipc_based_on_rob(self, window_size=[], data_source=None, save_output=False, last_level=None):
        max_parallel_inst = -1

        if data_source is None:
            data_source = self.parsedInst

        if last_level is None:
            data_portion = data_source
            dependency_matrix = self.extract_raw_dep(data_portion=data_portion)
            dependency_graph = self.extract_graph(dependency_matrix=dependency_matrix)
            [level_local, max_local] = self.find_levels(dependency_graph)
            max_parallel_inst = max(max_local, max_parallel_inst)
        else:
            level_local = last_level
            max_parallel_inst = -1

        ins_clk = self._cal_ipc(instruction_scheduler_window_sizes=window_size, levels=level_local)

        if save_output and last_level is None:
            suffix_name = "%d_%s" % (window_size, 'all')
            self.draw_html_table(data_portion=data_portion, dependency_matrix=dependency_matrix,
                                 suffix_name=suffix_name)
            self.export_graph_as_dot(data_portion=data_portion, dependency_graph=dependency_graph,
                                     suffix_name=suffix_name)
        if last_level is not None:
            level_local = None

        return [ins_clk, max_parallel_inst, level_local]

    def _cal_ipc(self, instruction_scheduler_window_sizes, levels):

        vals = list()
        from math import ceil

        for backend_instruction_windows_size in instruction_scheduler_window_sizes:
            cycles = 0
            print("Backed-end instruction scheduler windows size:{}".format(backend_instruction_windows_size))
            self.log_handler.info("Backed-end instruction scheduler windows size:{}"
                                  .format(backend_instruction_windows_size))
            total_inst = 0
            for level in levels:
                total_inst = total_inst + len(level)
                cycles = cycles + max(ceil(len(level)/backend_instruction_windows_size), 1)
            vals.append([total_inst, cycles])

        return vals
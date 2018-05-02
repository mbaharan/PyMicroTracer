class BasicBlockParser:

    def __init__(self, db_name, machine_mode, machine_arch, log_handler, offset=0,
                 how_many_bbl_should_be_analyzed=0, extract_level_in_details=False, prefix='./',
                 app_name='', based_on_bbl_id=True, log_output=False):

        from os.path import isdir, isfile
        from sys import exit
        self.log_handler = log_handler
        if isfile(db_name):
            self.dsn = 'DRIVER={SQLite3};SERVER=localhost;DATABASE=' + db_name + ';Trusted_connection=yes'
        else:
            exit("%s is not a file." % db_name)
        self.visitedBB = []
        self.howManyBB = 0
        self.BB = {}
        self.data = []
        if isdir(prefix):
            self.prefix = prefix
        else:
            self.prefix = './'
        self.log_output = log_output
        self.machineMode = machine_mode
        self.machineArch = machine_arch
        self.howManyBBshouldBeAnalyzed = how_many_bbl_should_be_analyzed
        self.BBid2BaseAddr = {}
        self.appName = app_name
        self.basedOnBBid = based_on_bbl_id
        self.levels = {}
        #        self.IPCperLevel = {}
        self.bb2lvl = {}
        self.offset = offset
        self.maxExecutedTime = -1
        self.extractLevelInDatails = extract_level_in_details

    def data_fetcher(self):
        if self.howManyBB == 0:
            self.howManyBB = self.extract_max_bb_number()
            if self.howManyBBshouldBeAnalyzed == 0 or self.howManyBBshouldBeAnalyzed > self.howManyBB:
                self.howManyBBshouldBeAnalyzed = self.howManyBB

            self.log_handler.info("Total number of BB that is going to be parssed=%d" % self.howManyBBshouldBeAnalyzed)

            if self.howManyBB > 0:
                for bbID in range(self.offset, (self.offset + self.howManyBBshouldBeAnalyzed + 2)):
                    data = self.fetch_inst_for_bbl_id(bbID)
                    self.analyze_bbls(data)

            self.log_handler.info("It is finished. Total BB# is %d." % self.howManyBB)

    def fetch_inst_for_bbl_id(self, bbl_id=-1):
        data = []
        import pyodbc
        if self.howManyBB >= 0 and self.howManyBB >= bbl_id:
            if self.dsn != '':
                localDbCon = pyodbc.connect(self.dsn)
                cr = localDbCon.cursor()
                strSrch = "SELECT CAST(bbl_id as 'TEXT') as bbl_id, ip, dis, op FROM ins"
                if bbl_id > -1:
                    strSrch = strSrch + (" WHERE ins.bbl_id=%d" % bbl_id)
                    if self.log_output:
                        self.log_handler.info("Retrieving instruction for BB#%d. Please wait..." % bbl_id)
                    cr.execute(strSrch)
                    data = cr.fetchall()
                    if self.log_output:
                        self.log_handler.info("Instruction for BB#%d have been fetched." % bbl_id)
                    cr.close()
        return data

    def extract_max_bb_number(self):
        import pyodbc
        db = pyodbc.connect(self.dsn)
        c = db.cursor()
        c.execute("SELECT CAST(MAX(bbl_id) AS'TEXT') AS howManyBB FROM ins;")
        data = c.fetchall()[0][0]
        return int(data)

    def analyze_bbls(self, data):

        def ops_ip(data):
            val = []
            for row in data:
                val.append([int(row[1], 16), row[3]])
            return val

        if len(data) > 0:
            bbAddr = int(data[0][1], 16)
            bbID = int(data[0][0])
            self.BBid2BaseAddr[bbID] = bbAddr
            if bbAddr not in self.BB:
                from PyMicroTracer.BasicBlock import BasicBlock
                import PyMicroTracer.Constant as cnst
                bb = BasicBlock(operations=ops_ip(data), machine_mode=self.machineMode, machine_arch=self.machineArch,
                                log_handler=self.log_handler, prefix=self.prefix, log_output=self.log_output,
                                bbl_id=bbID, bbl_base_addr=bbAddr)
                bb.skim_instructions()
                bb.extract_dependency([cnst.dep_raw()])
                bb.extract_graph()
                bb.extract_static_ipc()
                bb.alive_registers()
                self.BB[bbAddr] = bb
            else:
                self.BB[bbAddr].called_again()

    @property
    def basic_blocks(self):
        return dict(self.BB)  # pass it as new dictionary

    def extract_dependency_graph_between_bbl(self, start, end):
        import networkx as nx
        dependency_graph_between_bbl = nx.DiGraph()
        if len(self.BBid2BaseAddr) > 0:
            self.log_handler.info("Starting extracting BB graph dependencies...")

            only_jmp_bbl = []
            for bbl_id in range(end, start, -1):
                bbl_base_address = self.BBid2BaseAddr[bbl_id]
                read_from = self.BB[bbl_base_address].readRegsAtBoarder
                write_on = self.BB[bbl_base_address].writeRegsAtBoarder

                if self.basedOnBBid:
                    node = bbl_id
                else:
                    node = bbl_base_address

                if len(read_from) > 0 or len(write_on) > 0:
                    dependency_graph_between_bbl.add_node(node)
                else:
                    only_jmp_bbl.append(node)

            for dependent_bbl in range(end, start, -1):
                bbl_base_address_dp = self.BBid2BaseAddr[dependent_bbl]
                read_from = set(self.BB[bbl_base_address_dp].readRegsAtBoarder)
                if len(read_from):
                    for independent_bbl in range(dependent_bbl - 1, start, -1):
                        bbl_base_address_indp = self.BBid2BaseAddr[independent_bbl]
                        write_on = self.BB[bbl_base_address_indp].writeRegsAtBoarder

                        if len(write_on & read_from) > 0:
                            if self.basedOnBBid:
                                nodeDP = dependent_bbl
                                nodeIndp = independent_bbl
                            else:
                                nodeDP = bbl_base_address_dp
                                nodeIndp = bbl_base_address_indp

                            dependency_graph_between_bbl.add_edge(nodeIndp, nodeDP)
                            read_from = read_from - write_on
                            if len(read_from):
                                break
            self.log_handler.info("Finished extracting BB graph dependencies...")
            return dependency_graph_between_bbl

    def export_graph_as_dot(self, dependency_graph_between_bbl, levels=None, suffix='', save_as_pdf=False):
        if levels is None:
            levels = {}

        if dependency_graph_between_bbl.order():
            self.log_handler.info("Starting dumping BB graph dependencies as PDF...")
            from networkx.drawing.nx_agraph import write_dot
            import networkx as nx

            if len(levels) > 0:
                for i in levels.keys():
                    val = levels[i]
                    for nd in val:
                        if i % 2:
                            dependency_graph_between_bbl.node[nd]['color'] = 'red'
                        else:
                            dependency_graph_between_bbl.node[nd]['color'] = 'blue'

            base_file_name = self.prefix + 'depthGraph_bb' + suffix + self.appName
            write_dot(dependency_graph_between_bbl, base_file_name + '.dot')

            if save_as_pdf:
                import pydot
                (graph,) = pydot.graph_from_dot_file(base_file_name + '.dot')
                graph.write_pdf(base_file_name + '.pdf')
        else:
            self.log_handler.error("Cannot export graph as a PDF.")

    def extract_levels(self, dependency_graph_between_bbl):
        self.log_handler.info("Extracting levels...")
        import networkx as nx
        longest_path = nx.dag_longest_path(dependency_graph_between_bbl)
        level = len(longest_path)
        bb2lvl = {}
        levels = {}
        if self.extractLevelInDatails:
            levels[0] = {longest_path[0]}
            bb2lvl[longest_path[0]] = 0
            for lvl in range(0, level):
                children = set(nx.predecessor(dependency_graph_between_bbl, longest_path[lvl], cutoff=1))
                forbiden_child = set([])
                children = children - ({[longest_path[lvl]]} | {longest_path[lvl + 2:]})
                for child in children:
                    parents = nx.ancestors(dependency_graph_between_bbl, child)
                    if parents & children:
                        children = children - {[child]}

                levels[lvl + 1] = children

                for child in children:
                    self.bb2lvl[child] = lvl + 1
            restNodes = list(set(dependency_graph_between_bbl.nodes) - set(self.bb2lvl.keys()))
        else:
            for lvl in range(0, level):
                levels[lvl + 1] = -1

        return [levels, bb2lvl]

    def extract_total_ipc(self):
        total_ipc = 0
        max_ipc = None
        max_call = None
        if len(self.BB.values()):
            max_call = list(self.BB.values())[0]
            max_ipc = list(self.BB.values())[0]
            for bb in self.BB.values():
                total_ipc = (bb.IPC * bb.howManyCalled) + total_ipc
                if max_call.howManyCalled < bb.howManyCalled:
                    max_call = bb
                if max_ipc.IPC < bb.IPC:
                    max_ipc = bb

        total_ipc = total_ipc / self.howManyBBshouldBeAnalyzed
        if max_call is not None and max_ipc is not None:
            self.maxExecutedTime = "maxExecutedTime:%d, BB#%d" % (max_call.howManyCalled, max_call.bbID)
            self.log_handler.info("maxIPC:%d, BB#%d" % (max_ipc.IPC, max_ipc.bbID))
        else:
            self.maxExecutedTime = None
        return total_ipc

    def extract_ipc_at_bb_granularity(self, levels, start, end):
        num_lev = len(levels)
        ipc_per_level = {}
        sum_ipc = 0
        if self.extractLevelInDatails:
            if num_lev > 0:
                for key in levels.keys():
                    ipc = 0
                    for bbID in levels[key]:
                        bb_base_adr_dp = self.BBid2BaseAddr[bbID]
                        ipc = ipc + self.BB[bb_base_adr_dp].IPC

                    ipc_per_level[key] = ipc
                    sum_ipc = sum_ipc + ipc

            return [(sum_ipc / num_lev), ipc_per_level]
        else:
            for bbID in range(end, start, -1):
                bb_base_adr_dp = self.BBid2BaseAddr[bbID]
                sum_ipc = sum_ipc + self.BB[bb_base_adr_dp].IPC

            return [(sum_ipc / num_lev), ipc_per_level]

    def extract_ipc_for_bbl_size_width(self, power, save_dot_file=False):
        total = self.howManyBBshouldBeAnalyzed
        val = 2 ** power
        seg = int(total / val) + 1
        local_ipc = []
        if seg > 1:
            for idx in range(0, seg):
                start = (idx * val) + self.offset
                end = ((idx + 1) * val) + self.offset
                if end > self.howManyBB:
                    end = self.howManyBB

                if start < end:
                    dependency_graph = self.extract_dependency_graph_between_bbl(start, end)
                    [levels, b] = self.extract_levels(dependency_graph)
                    if save_dot_file:
                        self.export_graph_as_dot(dependency_graph_between_bbl=dependency_graph,
                                                 suffix=('%d_%d_%d' % (power, start, end)))
                    ipc = self.extract_ipc_at_bb_granularity(levels, start, end)
                    local_ipc.append(ipc[0])
        else:
            start = self.offset
            end = self.howManyBB
            dependency_graph = self.extract_dependency_graph_between_bbl(start, end)
            [levels, b] = self.extract_levels(dependency_graph)
            if save_dot_file:
                self.export_graph_as_dot(dependency_graph_between_bbl=dependency_graph,
                                         suffix=('%d_%d_%d' % (power, start, end)))
            ipc = self.extract_ipc_at_bb_granularity(levels, start, end)
            local_ipc.append(ipc[0])

        if len(local_ipc):
            avg_ipc = sum(local_ipc) / len(local_ipc)
        else:
            avg_ipc = local_ipc[0]

        return avg_ipc


if __name__ == "__main__":
    import time
    from PyMicroTracer import format_second
    import logging

    t0 = time.time()
    fileName = ['../example/arch/arm/hello_trace.db']
    res = ['../example/arch/arm/res/']
    from capstone import CS_ARCH_X86, CS_MODE_64

    howManyBB = 1232

    m_m = CS_MODE_64
    m_a = CS_ARCH_X86

    bbl_parser = BasicBlockParser(db_name=fileName[0], prefix=res[0], machine_arch=m_a, machine_mode=m_m,
                                  how_many_bbl_should_be_analyzed=howManyBB, based_on_bbl_id=True, log_handler=logging)
    bbl_parser.data_fetcher()
    print("total ipc: {0}".format(bbl_parser.extract_total_ipc()))
    bbl_parser.extract_ipc_for_bbl_size_width(power=3, save_dot_file=False)
    t1 = time.time()
    format_second(t1 - t0)

    print("finished")


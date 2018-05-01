"""
        Project: PyDGP
        File name: SuperBasicBlock
        Author: mbaharan -- 
        Email: 
        University of North Carolina at Charlotte
        Date:          Jan 15, 2018-12:57 PM
        Arguments:
        Outputs:
        Dependencies:
"""


import PyMicroTracer.Constant as cnst
from PyMicroTracer.Instruction import Instruction
import networkx as nx


class SuperBasicBlock:

    def __init__(self, db_file_name, start_from_bbl_id, machine_mode, machine_arch, log_handler, prefix_dir='./',
                 log_output=False):

        self.log_handler = log_handler

        from os.path import isdir, isfile
        if isfile(db_file_name):
            self.dsn = 'DRIVER={SQLite3};SERVER=localhost;DATABASE=' + db_file_name + ';Trusted_connection=yes'
        else:
            exit("%s is not a file." % db_file_name)

        self.parsedInst = []
        if start_from_bbl_id > -1:
            self.start_from_bbl_id = start_from_bbl_id
        else:
            self.start_from_bbl_id = -1

        if isdir(prefix_dir):
            self.prefix = prefix_dir
        else:
            self.prefix = './'

        self.log_output = log_output
        self.machineMode = machine_mode
        self.machineArch = machine_arch
        self.readRegsAtBoarder = set([])
        self.howManyParsedInst = 0
        self.longest_path = ''
        self.how_many_basic_block_has_been_read = 0
        self.last_bbl_id_has_been_read = 0
        self.IPC = 0
        self.how_many_cycle_needed = 0

    def fetch_instructions(self, end_bbl_id=-1):
        bbl_id = -1
        ins_count = 0
        end_bbl = self.start_from_bbl_id
        if -1 < end_bbl_id <= self.start_from_bbl_id:

            if self.dsn != '':
                import pyodbc
                local_db_con = pyodbc.connect(self.dsn)
                cr = local_db_con.cursor()
            else:
                self.log_handler.error("dsn is not set!")
                return

            bbl_id = self.start_from_bbl_id
            end_bbl = end_bbl_id

            while bbl_id >= end_bbl:
                str_query = "SELECT * FROM ins"
                str_query = str_query + (" WHERE ins.bbl_id=%d" % bbl_id)
                if self.log_output:
                    self.log_handler.debug("Retrieving instruction for BB#%d. Please wait..." % bbl_id)
                cr.execute(str_query)
                data = cr.fetchall()
                ins_count = ins_count + self.skim_instructions(data)
                bbl_id = bbl_id - 1
                if self.log_output:
                    self.log_handler.debug("Instruction for BB#%d have been fetched." % bbl_id)

        self.howManyParsedInst = ins_count
        self.how_many_basic_block_has_been_read = self.start_from_bbl_id - end_bbl
        self.last_bbl_id_has_been_read = end_bbl_id
        return bbl_id + 1

    def skim_instructions(self, data):
        count_local = 0
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
                    count_local = count_local + 1
                    if self.log_output:
                        self.log_handler.info(inst)
                else:
                    self.log_handler.debug("%s is useless!" % inst)
            else:
                self.log_handler.error("The instruction 0x%x can be not parsed!" % pc)
        return count_local

    def extract_raw_dep(self, data_portion=None):
        from capstone import CS_ARCH_X86

        if data_portion is None:
            data_portion = []
        self.log_handler.info("RAW dependency is started.")
        from PyMicroTracer.Dependency import Dependency

        row = 0
        col = 0

        if data_portion == -1:
            local_data = self.parsedInst
        else:
            local_data = data_portion

        total = len(data_portion)

        dependency_matrix = [[[] for j in range(total)] for i in range(total)]

        for rowInst in local_data:
            tmp = list(rowInst.readRegisters)
            if len(tmp) > 0:
                for colInst in local_data:
                    if row < col:
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
                                        arr = dependency_matrix[row][col]
                                        arr.append(dep)  # it acts like pointer in `C`
                                        tmp.remove(readReg)
                                        break
                            else:
                                if readReg in colInst.writeRegisters:
                                    dep = Dependency(rowInst.dictionaryForRegisters[readReg],
                                                     cnst.dep_raw())
                                    arr = dependency_matrix[row][col]
                                    arr.append(dep)  # it acts like pointer in `C`
                                    tmp.remove(readReg)
                    col = col + 1
            col = 0
            if len(tmp) > 0:
                for reg in tmp:
                    self.readRegsAtBoarder.add(reg)
            row = row + 1

        return dependency_matrix

    @staticmethod
    def extract_graph(dependency_matrix=[]):

        def is_there_dependency(inside_row):
            dep = False
            for col_inside in inside_row:
                if len(col_inside) > 0:
                    dep = True
                    break
            return dep

        if len(dependency_matrix) == 0:
            raise ValueError("Matrix size should not be zero!")

        dependency_graph = nx.DiGraph()
        if dependency_matrix != -1:
            for i in range(len(dependency_matrix)):
                dependency_graph.add_node(i)

            row_idx = 0
            col_idx = 0
            for row in dependency_matrix:
                if is_there_dependency(row):
                    for col in row:
                        if len(col) > 0:
                            dependency_graph.add_edge(col_idx, row_idx)
                        col_idx = col_idx + 1
                row_idx = row_idx + 1
                col_idx = 0

        return dependency_graph

    def export_graph_as_dot(self, data_portion=[], dependency_graph=None, suffix_name='', cluster_based_on_cycle=False):

        import pydot
        if dependency_graph != -1:

            from colour import Color
            grey = Color("#BEBEBE")
            dp_pydot = pydot.Dot(graph_type='digraph',
                                 fontname="Verdana")  # nx.drawing.nx_pydot.to_pydot(dependency_graph)
            [levels, non] = self.find_levels(dependency_graph.copy())

            if cluster_based_on_cycle:

                colors = list(grey.range_to(Color("#FFFFFF"), len(levels)))

                index = 0
                for level in levels:
                    cluster = pydot.Cluster('cycle{}'.format(index), label='cycle {}'.format(index),
                                            style='filled', color='"{}"'.format(colors[index]), shape="circle")
                    inst_id = 0
                    for node in level:
                        cluster.add_node(pydot.Node(node, label="BB# %d id= %d- %s" %
                                                                (data_portion[node].BBid, inst_id, data_portion[node])))
                        inst_id = inst_id + 1

                    index = index + 1
                    dp_pydot.add_subgraph(cluster)

                for nodes in dependency_graph.node:
                    edges = dependency_graph.edges(nodes)
                    for edge in edges:
                        dp_pydot.add_edge(pydot.Edge(edge[0], edge[1]))

                base_file_name = self.prefix + 'depthGraph_SuperBasicBlock' + suffix_name
                dp_pydot.write(base_file_name+'.dot')

            else:

                BBids = set()
                for inst in data_portion:
                    BBids.add(inst.BBid)

                colors = list(grey.range_to(Color("#FFFFFF"), len(BBids)))
                cluster = pydot.Cluster('cycles', label='cycles')

                for i in range(0, len(levels)):
                    cluster.add_node(pydot.Node('cycle{}'.format(i), label='cycle {}'.format(i)))

                for i in range(0, len(levels)-1):
                    cluster.add_edge(pydot.Edge('cycle{}'.format(i), 'cycle{}'.format(i+1)))

                dp_pydot.add_subgraph(cluster)

                index = 0
                for bb_id in BBids:
                    cluster = pydot.Cluster('bb{}'.format(bb_id), label='basic block {}'.format(bb_id))
                    for node in dependency_graph.node:
                        if data_portion[node].BBid == bb_id:
                            cluster.add_node(pydot.Node(node,
                                                        label="BB# %d - %s" % (data_portion[node].BBid,
                                                                               data_portion[node]),
                                                        style='filled', fillcolor='"{}"'.format(colors[index])))
                    dp_pydot.add_subgraph(cluster)
                    index = index + 1

                for nodes in dependency_graph.node:
                    edges = dependency_graph.edges(nodes)
                    for edge in edges:
                        dp_pydot.add_edge(pydot.Edge(edge[0], edge[1]))

                index=0
                for level in levels:
                    ranking = pydot.Subgraph(rank='same')
                    ranking.add_node(pydot.Node('cycle{}'.format(index)))
                    for node in dependency_graph.nodes:
                        if node in level:
                            ranking.add_node(pydot.Node(node))
                    index = index + 1
                    dp_pydot.add_subgraph(ranking)

                base_file_name = self.prefix + 'depthGraph_SuperBasicBlock' + suffix_name
                dp_pydot.write(base_file_name+'.dot')




    """
            if mark_longest_path:
                path = nx.dag_longest_path(dependency_graph)
                # for node in path:
                #    dependency_graph.node[int(node)]['color'] = 'red'
                for i in range(len(path) - 1):
                    dependency_graph[int(path[i])][int(path[i + 1])]['color'] = 'red'
                    dependency_graph[int(path[i])][int(path[i + 1])]['width'] = '8'

            if mark_levels:
                [levels, non] = self.find_levels(dependency_graph.copy())
                from colour import Color
                grey = Color("#F5DEB3")
                colors = list(grey.range_to(Color("#D2B48C"), len(levels)))
                i = 0
                for level in levels:

                    for node in level:
                        dependency_graph.node[int(node)]['style'] = 'filled'
                        dependency_graph.node[int(node)]['fillcolor'] = colors[i].get_hex()
                    i = i + 1

            labels = {}
            len_data = len(data_portion)
            i = 0
            for inst in data_portion:
                labels[i] = "%s - %d) %s" % (str(len_data-i), inst.BBid, inst)
                i = i + 1

            #renamed_graph = nx.relabel_nodes(dependency_graph, labels)
            #assert (renamed_graph.order() == len(data_portion))
            base_file_name = self.prefix + 'depthGraph_SuperBasicBlock' + suffix_name
            write_dot(dependency_graph, base_file_name + '.dot')
            write_dot(g, base_file_name + '_G.dot')

            if also_as_pdf:
                import pydot
                (graph,) = pydot.graph_from_dot_file(base_file_name + '.dot')
                graph.write_pdf(base_file_name + '.pdf')
        else:
            self.log_handler.error("Cannot export graph as a PDF.")
    """

    def extract_ipc(self, dependency_graph, fetch_width):
        if nx.is_directed(dependency_graph):
            self.log_handler.info("Extracting IPC...")
            lng_path = nx.dag_longest_path(dependency_graph)
            if self.log_output:
                self.log_handler.info("Longest path:%s\n" % str(lng_path))
            self.longest_path = str(lng_path)
            clock_per_level = len(lng_path)
            num_instruction = dependency_graph.order()
            clock_for_fetching = num_instruction / fetch_width
            self.how_many_cycle_needed = clock_per_level  # + clock_for_fetching
            self.IPC = num_instruction / self.how_many_cycle_needed



            # self.IPC = float( * (l+fetch_width / l*fetch_width))

    def draw_html_table(self, data_portion=[], dependency_matrix=None, suffix_name=''):
        import HTML
        header = list()
        header.append("Instructions")
        for ins in data_portion:
            header.append("%s" % (ins))
        row = []
        r_index = 0
        for ins in data_portion:
            inst_text = ["%s" % (ins)]
            row.append(inst_text + self.str_row_dependency(r_index, dependency_matrix, '<br/>'))
            r_index = r_index + 1
        row = [header] + row

        html_code = HTML.table(row, header)
        with open(self.prefix + "res" + suffix_name + ".html", "w") as file:
            file.write(html_code)

    @staticmethod
    def str_row_dependency(idx, dependency_matrix=-1, ending='\n'):
        arr = []
        val = ""
        for col in dependency_matrix[idx]:
            for dep in col:
                val = val + str(dep) + ending
            arr.append(val)
            val = ""
        return arr

    @staticmethod
    def find_levels(graph):
        levels = []
        max_parallel_inst = -1
        while graph.nodes():
            no_in_nodes = [n for (n, d) in list(graph.in_degree(graph.nodes())) if d == 0]
            levels.append(no_in_nodes)
            max_parallel_inst = max(len(no_in_nodes), max_parallel_inst)
            for n in no_in_nodes:
                graph.remove_node(n)
        return [levels, max_parallel_inst]

    def extract_ipc_based_on_rob(self, window_size=-1, fetch_width=8, data_source=None,
                                 save_output=False, save_local_level=False):
        if data_source is None:
            data_source = self.parsedInst

        total = len(data_source)

        max_parallel_inst = -1

        if window_size >= 0:
            val = window_size
        elif window_size < 0:
            val = total

        seg = int(total / val)
        local_cycle = []
        if seg > 0:
            for idx in range(0, seg):
                start = (idx * val)
                end = ((idx + 1) * val)
                if end > total:
                    end = total

                if start < end:
                    data_portion = data_source[start:end]
                    dependency_matrix = self.extract_raw_dep(data_portion=data_portion)
                    dependency_graph = self.extract_graph(dependency_matrix=dependency_matrix)
                    [level_local, max_local] = self.find_levels(dependency_graph.copy())

                    if save_local_level:
                        filename = self.prefix + "local_val.log"
                        with open(filename, "a") as log_file_level:
                            for level in level_local:
                                how_many = str(len(level)) + '\n'
                                log_file_level.writelines(how_many)

                    self.extract_ipc(dependency_graph=dependency_graph, fetch_width=fetch_width)
                    local_cycle.append(self.how_many_cycle_needed)
                    max_parallel_inst = max(max_local, max_parallel_inst)

                    if save_output:
                        suffix_name = "%d_%d" % (val, end)
                        self.draw_html_table(data_portion=data_portion, dependency_matrix=dependency_matrix,
                                             suffix_name=suffix_name)
                        self.export_graph_as_dot(data_portion=data_portion, dependency_graph=dependency_graph,
                                                 suffix_name=suffix_name)
        else:
            end = total
            data_portion = self.parsedInst
            dependency_matrix = self.extract_raw_dep(data_portion=data_portion)
            dependency_graph = self.extract_graph(dependency_matrix=dependency_matrix)
            self.extract_ipc(dependency_graph=dependency_graph, fetch_width=fetch_width)
            [level_local, max_local] = self.find_levels(dependency_graph.copy())
            max_parallel_inst = max(max_local, max_parallel_inst)

            if save_output:
                suffix_name = "%d_%d" % (val, end)
                y.draw_html_table(data_portion=data_portion, dependency_matrix=dependency_matrix,
                                  suffix_name=suffix_name)
                self.export_graph_as_dot(data_portion=data_portion, dependency_graph=dependency_graph,
                                         suffix_name=suffix_name)

            local_cycle.append(self.how_many_cycle_needed)

        if len(local_cycle) > 1:
            avg_ipc = self.howManyParsedInst / sum(local_cycle)
        else:
            avg_ipc = self.howManyParsedInst/local_cycle[0]

        return [avg_ipc, max_parallel_inst, seg]


if __name__ == "__main__":
    fileName = ['../example/arch/arm/hello_trace.db']
    res = ['../example/arch/arm/res/']
    lineStyle = ['r--']
    bchName = ['hello_world']
    maxBlock = [1232]
    from capstone import CS_ARCH_X86, CS_MODE_64
    from PyMicroTracer.Utility import plot_me
    import matplotlib.pyplot as plt
    import logging

    figAxis = plt.subplots()
    xTickBase = [5, 6]
    xTick = [(2 ** i) for i in xTickBase]
    xTickLabel = []
    dicIPC = {}
    m_m = CS_MODE_64
    m_a = CS_ARCH_X86

    for i in xTickBase:
        xTickLabel.append("$2^{%d}$" % i)

    for bncmark in range(0, 1):
        y = SuperBasicBlock(db_file_name=fileName[bncmark], start_from_bbl_id=1232, log_handler=logging,
                            machine_mode=m_m, machine_arch=m_a, prefix_dir=res[bncmark])
        offset = y.fetch_instructions(end_bbl_id=0)

        x = []
        IPC = []
        space = range(5, 7)
        totalSize = len(space)
        count = 0
        for power in space:
            x.append(2 ** power)
            avgIPC = y.extract_ipc_based_on_rob(2**power, save_output=True)
            IPC.append(avgIPC)
            count = count + 1
            print(("-----------> %3.1f%% passed." % (float(count) * 100 / totalSize)), end='\n', flush=True)

        print(IPC)
        dicIPC[bchName[bncmark]] = IPC
        plot_me(x=x, y=IPC, yScale=['log', 10], xTicks=xTick, xTickLabels=xTickLabel, xLabel='ROB Size', yLabel='IPC',
                  figAxis=figAxis, style=lineStyle[bncmark], label=bchName[bncmark])

    import csv

    with open(res[0] + 'dict.csv', 'wt') as csv_file:
        writer = csv.writer(csv_file)
        for key, value in dicIPC.items():
            writer.writerow([key, value])

    plt.show()

    print('finished')

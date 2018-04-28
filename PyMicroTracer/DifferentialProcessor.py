import progressbar


class DifferentialProcessor:

    def __init__(self, db_file_name, machine_mode, machine_arch, log_handler, batch_size=1000, how_many_iteration=-1,
                 prefix_dir='./', app_name='',
                 draw_dependency_graphs=False, log_output=True, fixed_instruction_windows_size=None,
                 scheduling_option=None, index_file=None):

        from os.path import isdir, isfile
        from sys import exit
        if isfile(db_file_name):
            self._db_file_name = db_file_name
            self._dsn = 'DRIVER={SQLite3};SERVER=localhost;DATABASE=' + db_file_name + ';Trusted_connection=yes'
        else:
            exit("%s is not a file." % db_file_name)

        if isdir(prefix_dir):
            self._prefix_dir = prefix_dir
        else:
            self._prefix_dir = './'

        self.index_file = index_file

        self._log_output = log_output
        self._machine_mode = machine_mode
        self._machine_arch = machine_arch
        self._maximum_number_of_bbl = 0
        self._draw_dependency_graphs = draw_dependency_graphs
        self._how_many_bbl_has_been_fetched = 0

        if batch_size > self.maximum_number_of_bbl:
            self._batch_size = self.maximum_number_of_bbl
        else:
            self._batch_size = batch_size

        self._how_many_iteration = how_many_iteration
        self._app_name = app_name
        self._log_handler = log_handler
        self.fixed_instruction_windows_size = fixed_instruction_windows_size
        self.scheduling_option = scheduling_option

        self.bar = progressbar.ProgressBar(widgets=['( {}: '.format(self._app_name), progressbar.Percentage(), ') [',
                                                    progressbar.Bar(),
                                                    '] [', progressbar.Timer(), ', ',
                                                    progressbar.ETA(), '] ',
                                                    ])#, redirect_stdout=True)

    @property
    def how_many_bbl_has_been_fetched(self):
        return self._how_many_bbl_has_been_fetched

    @property
    def maximum_number_of_bbl(self):
        if self._maximum_number_of_bbl:
            val = self._maximum_number_of_bbl
        else:
            import pyodbc
            db = pyodbc.connect(self._dsn)
            c = db.cursor()
            c.execute("SELECT MAX(bbl_id) AS howManyBB FROM ins;")
            data = c.fetchall()[0][0]
            val = data
            self._maximum_number_of_bbl = val
        return val

    def _get_max_idx(self):
        import math

        max_iteration = math.ceil(self.maximum_number_of_bbl / self._batch_size)

        if self._how_many_iteration <= 0:
            val = max_iteration
        else:
            val = min(max_iteration, self._how_many_iteration)

        return val

    def simulate_uniform(self, window_sizes=None, coverage=20):
        if not isinstance(window_sizes, type([])):
            exit("window size should list of positive integers")

        from numpy import zeros

        hybrid_ipc = None
        super_ipc = []
        static_ipc = []
        backend_end_size = 0

        if 0 < coverage <= 100:
            addresses = _generate_address(batch_size=self._batch_size, max_bbl_id=self.maximum_number_of_bbl,
                                          coverage=coverage, index_file=self.index_file)
        else:
            addresses = _generate_address(batch_size=self._batch_size, max_bbl_id=self.maximum_number_of_bbl,
                                          coverage=20, index_file=self.index_file)

        how_many_addr = len(addresses)
        count = 0
        total = len(window_sizes) * how_many_addr
        self.bar.update(0.0)
        prev_static_ipc = 0
        should_run_static = True

        max_parallel_inst_sbb = []
        max_parallel_inst_hb = []
        backend_window_size_all = []

        w_index = 0

        levels = []
        should_I_read_from_last_levels = False


        for window_size in window_sizes:
            self._log_handler.info("------------>window size:{}<------------".format(window_size))

            ipc_per_window_hyprid = None
            ipc_per_window_super = []
            static_ipc_per_window = []

            max_parallel_inst_hb_per_addr = -1
            max_parallel_inst_sbb_per_addr = -1

            for idx in range(0, how_many_addr):
                [start_from_bbl_id, end_bbl_id] = addresses[idx]

                if should_I_read_from_last_levels:
                    local_levels_hybrid = levels[idx]
                else:
                    local_levels_hybrid = None


                print("window size:{}, start_bbl_id={}, end_bbl_id={}".format(window_size, start_from_bbl_id
                                                                              , end_bbl_id))
                self._log_handler.info("window size:{}, start_bbl_id={}, end_bbl_id={}".format(window_size,
                                                                                               start_from_bbl_id,
                                                                                               end_bbl_id))

                [ipc_super, icc_hybrid, ipc_static, max_parallel_inst_sbb_per_ws, max_parallel_inst_hb_per_ws,
                 backend_window_size, offset] \
                    = self._simulate_behav(window_size=window_size, start_from_bbl_id=start_from_bbl_id,
                                           end_bbl_id=end_bbl_id, should_run_static=should_run_static,
                                           which_arch=self.scheduling_option)

                if ipc_per_window_hyprid is None and icc_hybrid.any():
                    backend_end_size = len(icc_hybrid)
                    ipc_per_window_hyprid = zeros((how_many_addr, backend_end_size))
                #else:
                #    backend_end_size = 0
                #    ipc_per_window_hyprid = zeros((how_many_addr, backend_end_size))

                if hybrid_ipc is None and icc_hybrid.any():
                    hybrid_ipc = zeros((len(window_sizes), len(icc_hybrid)))

                max_parallel_inst_hb_per_addr = max(max_parallel_inst_hb_per_addr, max_parallel_inst_hb_per_ws)
                max_parallel_inst_sbb_per_addr = max(max_parallel_inst_sbb_per_addr, max_parallel_inst_sbb_per_ws)

                ipc_per_window_super.append(ipc_super)
                if icc_hybrid.any():
                    ipc_per_window_hyprid[idx, :] = icc_hybrid[:, 0]
                static_ipc_per_window.append(ipc_static)

                count = count + 1
                self.bar.update(count * 100 / total)

            max_parallel_inst_sbb.append(max_parallel_inst_sbb_per_addr)
            max_parallel_inst_hb.append(max_parallel_inst_hb_per_addr)

            for idx in range(0, backend_end_size):
                hybrid_ipc[w_index, idx] = sum(ipc_per_window_hyprid[:, idx]) / how_many_addr

            w_index = w_index + 1

            if len(ipc_per_window_super):
                super_ipc.append(sum(ipc_per_window_super)/len(ipc_per_window_super))

            if should_run_static:
                if len(static_ipc_per_window):
                    static_ipc.append(sum(static_ipc_per_window)/len(static_ipc_per_window))
                    prev_static_ipc = sum(static_ipc_per_window) / len(static_ipc_per_window)
            else:
                static_ipc.append(prev_static_ipc)

            should_run_static = False

            backend_window_size_all.append(backend_window_size)

            should_I_read_from_last_levels = True

        return [hybrid_ipc, super_ipc, static_ipc, max_parallel_inst_hb, max_parallel_inst_sbb,
                backend_window_size_all]

    def _simulate_behav(self, window_size, start_from_bbl_id, end_bbl_id, should_run_static=True,
                        last_levels_hybrid=None, which_arch=set(['S', 'H', 'O'])):

        from PyMicroTracer.SuperBasicBlock import SuperBasicBlock
        from PyMicroTracer.HybridBasicBlock import HybridBasicBlock
        from PyMicroTracer.StaticBasicBlock import BasicBlockParser

        ipc_super = []
        icc_hybrid = []
        ipc_static = []
        offset = -1
        max_parallel_inst_sbb = -1
        max_parallel_inst_hb = -1

        backend_window_size = self._calculate_instr_window_size(window_size)

        if 'H' in which_arch:
            hbb = HybridBasicBlock(db_file_name=self._db_file_name, start_from_bbl_id=start_from_bbl_id,
                                   machine_mode=self._machine_mode, machine_arch=self._machine_arch,
                                   log_handler=self._log_handler,
                                   instruction_scheduler_window_size=backend_window_size,
                                   prefix_dir=self._prefix_dir, log_output=self._log_output)
            offset = hbb.fetch_instructions(end_bbl_id=end_bbl_id)
            print("Extracting IPC for hybrid bbl...")
            self._log_handler.info("Extracting IPC for hybrid bbl...")
            [icc_hybrid, max_parallel_inst_hb] = hbb.extract_ipc_based_on_bbl(bbl_size_scheduler=window_size)
            del hbb

        if 'O' in which_arch:
            sbb = SuperBasicBlock(db_file_name=self._db_file_name, start_from_bbl_id=start_from_bbl_id,
                                  machine_mode=self._machine_mode, machine_arch=self._machine_arch,
                                  log_handler=self._log_handler,
                                  prefix_dir=self._prefix_dir, log_output=self._log_output)
            sbb.fetch_instructions(end_bbl_id=end_bbl_id)
            print("Extracting IPC for super bbl...")
            self._log_handler.info("Extracting IPC for super bbl...")
            [ipc_super, max_parallel_inst_sbb] = sbb.extract_ipc_based_on_rob(window_size=window_size,
                                                                              save_output=self._draw_dependency_graphs)
            del sbb

        if 'S' in which_arch and should_run_static:
            st_bbl = BasicBlockParser(db_name=self._db_file_name, machine_mode=self._machine_mode,
                                      machine_arch=self._machine_arch,
                                      log_handler=self._log_handler, offset=offset,
                                      how_many_bbl_should_be_analyzed=self._batch_size, prefix=self._prefix_dir,
                                      app_name=self._app_name, log_output=self._log_output)
            st_bbl.data_fetcher()
            print("Extracting IPC for static bbl...")
            self._log_handler.info("Extracting IPC for static bbl...")
            ipc_static = st_bbl.extract_total_ipc()
            del st_bbl

        return [ipc_super, icc_hybrid, ipc_static, max_parallel_inst_sbb, max_parallel_inst_hb,
                backend_window_size, offset]

    def _calculate_instr_window_size(self, bbl_window_size):

        if self.fixed_instruction_windows_size:
            return self.fixed_instruction_windows_size
        else:
            from math import log2, ceil
            a = 3.634
            b = 0.6209
            p = log2(bbl_window_size)
            return [ceil(a * (2 ** (b * p)))]


def _generate_address(batch_size, max_bbl_id, coverage, index_file=None):

    import random
    addresses = []

    if index_file is not None:
        print("Reading indices file.")
        import gzip

        with gzip.open(index_file, 'rt') as file:
            for line in file:
                if line.startswith('#@#'):
                    data = line.split(' ')
                    end = int(data[1].strip('\t\r\n'))
                    start = min(end + (batch_size-1), max_bbl_id)
                    addresses.append([start, end])
        return addresses

    how_many_segment = int(max_bbl_id / batch_size)

    how_many_end_point = int(how_many_segment*coverage/100)

    end_addresses_idx = random.sample(range(1, how_many_segment+1), how_many_end_point)

    for i in range(0, len(end_addresses_idx)):
        end = int(max(max_bbl_id - end_addresses_idx[i]*batch_size, 0))
        start = min(end + batch_size, max_bbl_id)
        addresses.append([start, end])

    return addresses

#!/usr/bin/python3

__author__ = "Reza Baharani"
__copyright__ = "TeCSAR Group, Copyright 2018"
__credits__ = ["Reza Baharani"]
__license__ = "MIT"
__version__ = "1.0.0"
__maintainer__ = "Reza Baharani"
__email__ = "mbaharan@uncc.edu"
__status__ = "Research"

from PyMicroTracer import DifferentialProcessor, plot_me, format_second, save_result_as_csv
from capstone import CS_ARCH_X86, CS_MODE_64
import time
import matplotlib.pyplot as plt
import logging

if __name__ == "__main__":

    from PyMicroTracer.ArgumentsChecker import args, get_window_sizes

    ins_line_style = ['b:']
    hybrid_line_style = ['r:']
    static_line_style = ['k:']
    max_scheduled_inst_hbb = ['ko']
    max_scheduled_inst_sbp = ['kx']

    [min_w, max_w] = get_window_sizes(args.window_size)
    fix_b_window = []
    if args.backend_instruction_windows_size:
        [min_wb, max_wb] = get_window_sizes(args.backend_instruction_windows_size)
        fix_b_window = sorted([2**i for i in range(min_wb, max_wb+1)], reverse=True)

    powers = sorted([i for i in range(min_w, max_w+1)], reverse=True)
    window_sizes = [2**power for power in powers]

    coverage = float(args.coverage)
    batch_size = 10*max(window_sizes)

    fig_axis = plt.subplots()

    t0 = time.time()

    machine_mode = CS_MODE_64
    machine_arch = CS_ARCH_X86

    print('Working on: {}'.format(args.application_name))
    dict_per_bnch={}
    frmt = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"

    logging.basicConfig(format=frmt, filename=args.result_directory+args.application_name+'_info.log',
                        level=logging.INFO)
    logging.basicConfig(format=frmt, filename=args.result_directory+args.application_name+'_warn.log',
                        level=logging.WARN)
    logging.basicConfig(format=frmt, filename=args.result_directory+args.application_name+'_err.log',
                        level=logging.ERROR)
    logging.basicConfig(format=frmt, filename=args.result_directory+args.application_name+'_debug.log',
                        level=logging.DEBUG)

    dp = DifferentialProcessor(db_file_name=args.trace_file, machine_mode=machine_mode, machine_arch=machine_arch,
                               log_handler=logging,  batch_size=batch_size, how_many_iteration=-1,
                               prefix_dir=args.result_directory, draw_dependency_graphs=args.draw_dependency_graph,
                               app_name=args.application_name, log_output=False,
                               fixed_instruction_windows_size=fix_b_window,
                               scheduling_option=args.scheduling_method, index_file=args.index_file)

    whole_ipc = dp.simulate_uniform(window_sizes=window_sizes, coverage=coverage)

    if args.plot:

        x_tick_labels = []
        for i in powers:
            x_tick_labels.append("$2^{%d}$" % i)

        y_scale = []  # ['log', 10]

        x2_tick_labels = []
        for b_i_s_w in whole_ipc[5]:
            x2_tick_labels.append(b_i_s_w)

        if 'H' in args.scheduling_method:
            plot_me(x=window_sizes, y=whole_ipc[0], yScale=y_scale, xTicks=window_sizes, xTickLabels=x_tick_labels,
                    xLabel='Window Size', yLabel='IPC', figAxis=fig_axis, style=hybrid_line_style[0],
                    label=args.application_name+" hyprid-bbl", legenLoc="upper left", x2=whole_ipc[5],
                    x2TickLabels=x2_tick_labels, x2Ticks=whole_ipc[5])

        if 'O' in args.scheduling_method:
            plot_me(x=window_sizes, y=whole_ipc[1], yScale=y_scale, xTicks=window_sizes, xTickLabels=x_tick_labels,
                    xLabel='Window Size', yLabel='IPC', figAxis=fig_axis, style=ins_line_style[0],
                    label=args.application_name+" super-bbl", legenLoc="upper left", x2=whole_ipc[5],
                    x2TickLabels=x2_tick_labels, x2Ticks=whole_ipc[5])

        if 'S' in args.scheduling_method:
            plot_me(x=window_sizes, y=whole_ipc[2], yScale=y_scale, xTicks=window_sizes, xTickLabels=x_tick_labels,
                    xLabel='Window Size', yLabel='IPC', figAxis=fig_axis, style=static_line_style[0],
                    label=args.application_name + " static-bbl", legenLoc="upper left", x2=whole_ipc[5],
                    x2TickLabels=x2_tick_labels, x2Ticks=whole_ipc[5])

    #plot_me(x=window_sizes, y=whole_ipc[3], yScale=y_scale, xTicks=window_sizes, xTickLabels=x_tick_labels,
    #        xLabel='Window Size', yLabel='IPC', figAxis=fig_axis, style=max_scheduled_inst_hbb[idx],
    #        label=args.application_name + " max schld instr hbb", legenLoc="upper left")
    #
    #plot_me(x=window_sizes, y=whole_ipc[4], yScale=y_scale, xTicks=window_sizes, xTickLabels=x_tick_labels,
    #        xLabel='Window Size', yLabel='IPC', figAxis=fig_axis, style=max_scheduled_inst_sbp[idx],
    #        label=args.application_name + " max schld instr sbb", legenLoc="upper left")

    back_end_str = ''

    if 'H' in args.scheduling_method:
        h_ipc = whole_ipc[0]
        if len(whole_ipc[5][0]) > 1:
            for b_idx in range(0, len(whole_ipc[5][0])):
                back_end_str = str(whole_ipc[5][b_idx])
                dict_per_bnch["hybrid_"+back_end_str] = h_ipc[:, b_idx]
        else:
            dict_per_bnch["hybrid"] = h_ipc[:, 0]

    if 'O' in args.scheduling_method:
        dict_per_bnch["super"] = whole_ipc[1]
    if 'S' in args.scheduling_method:
        dict_per_bnch["static"] = whole_ipc[2]

    dict_per_bnch["max_sched_hbb" + back_end_str] = list(whole_ipc[3])
    dict_per_bnch["max_sched_sbb"] = whole_ipc[4]
    dict_per_bnch["windows"] = window_sizes
    dict_per_bnch["back_windows"] = whole_ipc[5]

    print(whole_ipc)
    file_name = args.result_directory + args.application_name

    file_name = file_name + ".csv"

    save_result_as_csv(dict_per_bnch, file_name)

    t1 = time.time()
    format_second(t1 - t0)

    if args.plot:
        plt.show()


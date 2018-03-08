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
from capstone import CS_ARCH_X86, CS_MODE_64, CS_MODE_ARM, CS_MODE_V8, CS_ARCH_ARM
import time
import matplotlib.pyplot as plt
import logging
import argparse
import functools
import os


def readable_dir(prospective_dir):
    if not os.path.isdir(prospective_dir):
        raise Exception("readable_dir:{0} is not a valid path".format(prospective_dir))
    if os.access(prospective_dir, os.R_OK):
        return prospective_dir
    else:
        raise Exception("readable_dir:{0} is not a readable dir".format(prospective_dir))


def check_range(value, min_val, max_val):
    try:
        f_value = float(value)
    except ValueError as err:
        raise argparse.ArgumentTypeError(str(err))

    if not min_val < f_value <= max_val:
        raise argparse.ArgumentTypeError("%s is not a in the range of (0, 1].".format(value))
    return f_value


def check_window_size(value):
    nums = value.split(',')

    try:
        min_w = int(nums[0])
        max_w = int(nums[1])
    except ValueError as err:
        raise argparse.ArgumentTypeError(str(err))

    if min_w >= max_w:
        raise argparse.ArgumentTypeError("{} should be less than {}". format(min_w, max_w))


def get_window_sizes(value):
    nums = value.split(',')
    min_w = int(nums[0])
    max_w = int(nums[1])

    return [min_w, max_w]


def extant_file(value):
    """
    'Type' for argparse - checks that file exists but does not open.
    """
    if not os.path.exists(value):
        # Argparse uses the ArgumentTypeError to give a rejection message like:
        # error: argument input: x does not exist
        raise argparse.ArgumentTypeError("{0} does not exist".format(value))
    return value


check_coverage = functools.partial(check_range, min=0, max=1)


parser = argparse.ArgumentParser()
parser.add_argument("-t", "--trace_file", help="Trace file in sqlite database format. Please refer to PyArmTracer project for \n"
                                "more information.", type=extant_file)
parser.add_argument("-c", help="Coverage percent of trace file. A float number between (0, 1].",
                    type=check_coverage)

parser.add_argument("-w", help="Window size range. For example --w=5,7 means that windows size will change\n"
                                " from 5 to 7.")
parser.add_argument("-r", "--result_directory", help="A directory path for saving log files and results.",
                    type=readable_dir)

parser.add_argument("-n", "--application_name", help="Application name.")

parser.add_argument("-v", "--verbose", help="Increase output verbosity", action="store_true")
args = parser.parse_args()


if __name__ == "__main__":

    ins_line_style = ['b:']
    hybrid_line_style = ['r:']
    static_line_style = ['k:']
    max_scheduled_inst_hbb = ['ko']
    max_scheduled_inst_sbp = ['kx']

    [min_w, max_w] = get_window_sizes(args.w)

    powers = [i for i in range(min_w, max_w+1)]
    window_sizes = [2**power for power in powers]

    coverage = float(args.c)
    batch_size = 2*max(powers)

    fig_axis = plt.subplots()

    x_tick_labels = []
    for i in powers:
        x_tick_labels.append("$2^{%d}$" % i)

    t0 = time.time()

    machine_mode = CS_MODE_ARM + CS_MODE_V8
    machine_arch = CS_ARCH_ARM

    print('Working on: {}'.format(args.application_name))
    dict_per_bnch={}
    frmt = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(format=frmt, filename=args.result_directory+args.application_name+'_info.log', level=logging.INFO)
    logging.basicConfig(format=frmt, filename=args.result_directory+args.application_name+'_warn.log', level=logging.WARN)
    logging.basicConfig(format=frmt, filename=args.result_directory+args.application_name+'_err.log', level=logging.ERROR)
    logging.basicConfig(format=frmt, filename=args.result_directory+args.application_name+'_debug.log', level=logging.DEBUG)

    dp = DifferentialProcessor(db_file_name=args.trace_file, machine_mode=machine_mode, machine_arch=machine_arch,
                               log_handler=logging,  batch_size=batch_size, how_many_iteration=-1,
                               prefix_dir=args.result_directory, draw_dependency_graphs=False, app_name=args.application_name,
                               log_output=False)

    whole_ipc = dp.simulate_uniform(window_sizes=window_sizes, coverage=coverage)

    y_scale = []  # ['log', 10]

    x2_tick_labels = []
    for b_i_s_w in whole_ipc[5]:
        x2_tick_labels.append(b_i_s_w)

    print(x2_tick_labels)

    plot_me(x=window_sizes, y=whole_ipc[0], yScale=y_scale, xTicks=window_sizes, xTickLabels=x_tick_labels,
            xLabel='Window Size', yLabel='IPC', figAxis=fig_axis, style=hybrid_line_style[idx],
            label=args.application_name+" hyprid-bbl", legenLoc="upper left", x2=whole_ipc[5],
            x2TickLabels=x2_tick_labels, x2Ticks=whole_ipc[5])

    plot_me(x=window_sizes, y=whole_ipc[1], yScale=y_scale, xTicks=window_sizes, xTickLabels=x_tick_labels,
            xLabel='Window Size', yLabel='IPC', figAxis=fig_axis, style=ins_line_style[idx],
            label=args.application_name+" super-bbl", legenLoc="upper left", x2=whole_ipc[5],
            x2TickLabels=x2_tick_labels, x2Ticks=whole_ipc[5])

    plot_me(x=window_sizes, y=whole_ipc[2], yScale=y_scale, xTicks=window_sizes, xTickLabels=x_tick_labels,
            xLabel='Window Size', yLabel='IPC', figAxis=fig_axis, style=static_line_style[idx],
            label=args.application_name + " static-bbl", legenLoc="upper left", x2=whole_ipc[5],
            x2TickLabels=x2_tick_labels, x2Ticks=whole_ipc[5])

        #plot_me(x=window_sizes, y=whole_ipc[3], yScale=y_scale, xTicks=window_sizes, xTickLabels=x_tick_labels,
        #        xLabel='Window Size', yLabel='IPC', figAxis=fig_axis, style=max_scheduled_inst_hbb[idx],
        #        label=args.application_name + " max schld instr hbb", legenLoc="upper left")
#
        #plot_me(x=window_sizes, y=whole_ipc[4], yScale=y_scale, xTicks=window_sizes, xTickLabels=x_tick_labels,
        #        xLabel='Window Size', yLabel='IPC', figAxis=fig_axis, style=max_scheduled_inst_sbp[idx],
        #        label=args.application_name + " max schld instr sbb", legenLoc="upper left")

    dict_per_bnch["hybrid"] = whole_ipc[0]
    dict_per_bnch["super"] = whole_ipc[1]
    dict_per_bnch["static"] = whole_ipc[2]
    dict_per_bnch["max_sched_hbb"] = whole_ipc[3]
    dict_per_bnch["max_sched_sbb"] = whole_ipc[4]
    dict_per_bnch["windows"] = window_sizes

    print(whole_ipc)
    file_name = args.result_directory + args.application_name + ".csv"
    save_result_as_csv(dict_per_bnch, file_name)

    t1 = time.time()
    format_second(t1 - t0)

    plt.show()


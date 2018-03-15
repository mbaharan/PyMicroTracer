import functools
import os
import argparse


def readable_dir(prospective_dir):
    if not os.path.isdir(prospective_dir):
        raise argparse.ArgumentTypeError("readable_dir:{0} is not a valid path".format(prospective_dir))
    if os.access(prospective_dir, os.R_OK):
        return prospective_dir
    else:
        raise argparse.ArgumentTypeError("readable_dir:{0} is not a readable dir".format(prospective_dir))


def check_range(value, min_val, max_val):
    try:
        f_value = float(value)
    except ValueError as err:
        raise argparse.ArgumentTypeError("{} is not a float number.".format(value))

    if not min_val < f_value <= max_val:
        raise argparse.ArgumentTypeError("{} is not in the range of (0, 1].".format(value))
    return f_value


def check_window_size(value):

    try:
        nums = value.split(',')
        min_w = int(nums[0])
        max_w = int(nums[1])
    except IndexError as err:
        raise argparse.ArgumentTypeError("'{}' is not in the right format. Please see document or run the main with `-h`"
                                         "\n option.".format(value))
    except ValueError as err:
        raise argparse.ArgumentTypeError("One of '{}' part has not an integer value.".format(value))

    if min_w > max_w:
        raise argparse.ArgumentTypeError("'{}' is not less than or equal to '{}'.". format(min_w, max_w))

    return value


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


def check_scheduling(value):
    right_values = set()
    try:
        schs = value.split(',')
        for sch in schs:
            SCH = sch.upper()
            if SCH in ['H', 'S', 'O']:
                right_values.add(SCH)
    except IndexError:
        raise argparse.ArgumentTypeError("'{}' is not in the right format. Please see document or "
                                         "run the main with `-h`\n option.".format(value))

    if len(right_values) == 0:
        right_values |= set(['H', 'S', 'O'])

    return list(right_values)


check_coverage = functools.partial(check_range, min_val=0, max_val=100)


parser = argparse.ArgumentParser()
parser.add_argument("trace_file", help="Trace file in sqlite database format. Please refer to PyArmTracer project for"
                                       " \n more information.", type=extant_file)
parser.add_argument("coverage", help="Coverage percentage of trace file. ",
                    type=check_coverage)

parser.add_argument("window_size", help="Window size range. For example, when window_size is 5,7 means that windows \n"
                                        "size will change from 5 to 7.", type=check_window_size)

parser.add_argument("result_directory", help="A directory path for saving log files and results.",
                    type=readable_dir)

parser.add_argument("application_name", help="Application name.")

parser.add_argument("-d", "--draw_dependency_graph", help="Draws data dependency graph in `dot` format files.",
                    action="store_true")

parser.add_argument("-b", "--backend_instruction_windows_size", help="Only for hybrid model. If you want to define a "
                                                                     "fixed back-end instruction window size, use this "
                                                                     "option.", type=int)

parser.add_argument("-s", "--scheduling_method", help="There are three different scheduling options as follows:"
                                                      "\n\t O: Out-of-order."
                                                      "\n\t S: Static scheduling."
                                                      "\n\t H: Hybrid scheduling."
                                                      "If user wants to analyze both out-of-order and "
                                                      "hybrid scheduling, he/she should pass the argument as follows:"
                                                      "\n\t -s O,H", type=check_scheduling)


args = parser.parse_args()

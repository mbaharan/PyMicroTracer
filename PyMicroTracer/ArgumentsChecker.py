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

parser.add_argument("-d", "--draw_dependency_graph", help="Increase output verbosity", action="store_true")

args = parser.parse_args()

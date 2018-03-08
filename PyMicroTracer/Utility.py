"""
        Project: PyDGP
        File name: Utility
        Author: mbaharan -- 
        Email: 
        University of North Carolina at Charlotte
        Date:          Jan 16, 2018-4:46 PM
        Arguments:
        Outputs:
        Dependencies: 
"""

import networkx as nx
import numpy as np


def find_lowest_common_decendent(graph, a, b):
    """
    Find the lowest common ancestor in the directed, acyclic graph of node a and b.
    The LCA is defined as on

    @reference:
    https://en.wikipedia.org/wiki/Lowest_common_ancestor

    Notes:
    ------
    This definition is the opposite of the term as it is used e.g. in biology!

    Arguments:
    ----------
        graph: networkx.DiGraph instance
            directed, acyclic, graph

        a, b:
            node IDs

    Returns:
    --------
        lca: [node 1, ..., node n]
            list of lowest common ancestor nodes (can be more than one)
    """

    assert nx.is_directed_acyclic_graph(graph), "Graph has to be acyclic and directed."

    # get ancestors of both (intersection)
    common_ancestors = list(nx.descendants(graph, a) & nx.descendants(graph, b))

    # get sum of path lengths
    sum_of_path_lengths = np.zeros((len(common_ancestors)))
    for ii, c in enumerate(common_ancestors):
        sum_of_path_lengths[ii] = nx.shortest_path_length(graph, a, c) \
                                  + nx.shortest_path_length(graph, b, c)

    # print common_ancestors
    # print sum_of_path_lengths

    # return minima
    try:
        minima, = np.where(sum_of_path_lengths == np.min(sum_of_path_lengths))
        return [common_ancestors[ii] for ii in minima]
    except ValueError:
        return -1


# https://reformatcode.com/code/python/lowest-common-ancestor-in-python39s-networkx

def find_lowest_common_ancestor(graph, a, b):
    assert nx.is_directed_acyclic_graph(graph), "Graph has to be acyclic and directed."

    preds_1 = nx.bfs_predecessors(graph, a)
    preds_2 = nx.bfs_predecessors(graph, b)

    common_preds = set([n for n in preds_1]).intersection(set([n for n in preds_2]))

    if len(list(preds_1)) > 0 and len(common_preds) > 0:
        min(common_preds, key=lambda n: preds_1[n])
    else:
        return -1


def which_node_can_be_executed_next(graph, node, hasBeenExecuted):
    assert nx.is_directed_acyclic_graph(graph), "Graph has to be acyclic and directed."

    childs = (list(nx.bfs_successors(graph, node))[0])[1]  # find its first childs.

    '''
    check other childs have other parents or not
    '''
    val = []
    for child in childs:
        par = nx.ancestors(graph, child)
        if par <= hasBeenExecuted:  # check if pas is a subset of hasBeenExecuted.
            val.append(child)
    return val


def plot_me(x, y, figAxis, style='k--', xLabel='', yLabel='', label='', yScale=[], xTicks=[], xTickLabels=[], x2=[],
            x2Ticks=[], x2TickLabels=[], legenLoc='lower right', legenFontSize='large', legendFaceColor='#00FFCC'):
    fig, ax = figAxis
    ax.set_xlabel(xLabel)
    ax.set_ylabel(yLabel)

    ax.plot(x, y, style, label=label)

    if yScale:
        ax.set_yscale(yScale[0], basex=yScale[1])

    ax.set_xscale('log', basex=2, nonposx='clip')

    if xTicks:
        ax.set_xticks(xTicks)

    ax.get_xaxis().get_major_formatter().labelOnlyBase = False

    ax.spines['top'].set_color('red')

    if len(x2) == len(x):
        ax2 = ax.twiny()
        ax2.plot(x, y, style, label=label)
        ax2.set_xscale('log', basex=2, nonposx='clip')
        ax2.set_xticks(xTicks)
        ax2.get_xaxis().get_major_formatter().labelOnlyBase = False
        ax2.set_xticklabels(x2TickLabels)
        ax2.set_xlabel("Back-end Instruction Scheduler")
        ax2.xaxis.grid()
        ax2.yaxis.grid()
        ax2.title.set_color('red')
        ax2.tick_params(axis='x', colors='red', which='both')
        ax2.xaxis.label.set_color('red')

    if xTickLabels:
        ax.set_xticklabels(xTickLabels)

    ax.yaxis.grid()  # horizontal lines
    ax.xaxis.grid()

    legend = ax.legend(loc=legenLoc, shadow=True, fontsize=legenFontSize)

    legend.get_frame().set_facecolor(legendFaceColor)


def format_second(elp):
    day = elp // (24 * 3600)
    time = elp % (24 * 3600)
    hour = elp // 3600
    time %= 3600
    minutes = elp // 60
    elp %= 60
    seconds = elp
    print("d:h:m:s-> %d:%d:%d:%d" % (day, hour, minutes, seconds))


def save_result_as_csv(dictionary, file_name):
    import csv
    with open(file_name, 'wt') as csv_file:
        writer = csv.writer(csv_file)
        for key, value in dictionary.items():
            writer.writerow([key, value])


def read_result_from_csv(file_name):
    import csv
    import ast
    val = dict()
    with open(file_name, 'rt') as csv_file:
        reader = csv.reader(csv_file)
        my_dict = dict(reader)

    for key in my_dict.keys():
        val_per_key = ast.literal_eval(my_dict[key])
        val[key] = [float(i) for i in val_per_key]

    return val


if __name__ == "__main__":
    file_name = "/media/mbaharan/d80cc718-89ff-4d55-9add-8596bd15cb9a/testSpec2000/parser/res/parser.csv"
    parser = read_result_from_csv(file_name=file_name)
    print(parser)
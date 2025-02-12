import igraph


def handler(event):
    size = event.get('size')

    graph = igraph.Graph.Barabasi(size, 10)

    result = graph.spanning_tree(None, False)


# handler({'size': 100000})
fn_name = 'testcases/fn_py_mst'

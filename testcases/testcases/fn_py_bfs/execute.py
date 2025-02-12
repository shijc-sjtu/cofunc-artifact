import igraph


def handler(event):
    size = event.get('size')

    graph = igraph.Graph.Barabasi(size, 10)

    result = graph.bfs(0)


# handler({'size': 100000})
fn_name = 'testcases/fn_py_bfs'

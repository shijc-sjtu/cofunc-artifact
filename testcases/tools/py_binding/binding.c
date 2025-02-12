#include <Python.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#include "lean_container.h"

static PyObject *sc_fork_lean_container(PyObject *self, PyObject *args)
{
    const char *name;
    const char *rootfs_path;
    pid_t pid;

    if (!PyArg_ParseTuple(args, "ss", &name, &rootfs_path))
        return NULL;

    pid = setup_lean_container_w_double_fork(name, rootfs_path, -1);

    return PyLong_FromLong(pid);
}

static PyMethodDef sc_methods[] = {
    {"fork_lean_container", sc_fork_lean_container, METH_VARARGS, ""},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef sc_module = {
    PyModuleDef_HEAD_INIT,
    "sc",
    "Python interface for split container",
    -1,
    sc_methods
};

PyMODINIT_FUNC PyInit_sc(void)
{
    return PyModule_Create(&sc_module);
}

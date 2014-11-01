#include "Python.h"
#include <port3.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>


static PyObject *
lescan(PyObject *self, PyObject *args) {

    PyObject *rtn_list = PyList_New(0);

    return rtn_list;
}

static PyMethodDef ble_methods[] = {
    {"lescan", lescan, METH_VARARGS, "lescan() doc string"},
    {NULL, NULL}
};

static struct PyModuleDef blemodule = {
    PyModuleDef_HEAD_INIT,
    "ble",
    "bluetooth low energy module",
    -1,
    ble_methods,
    NULL,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC
PyInit_ble(void)
{
    return PyModule_Create(&blemodule);
}

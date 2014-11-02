#include "Python.h"
#include "ble.h"
#include <port3.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>


PyObject *
bt_lescan(PyObject *self, PyObject *args) {
    PyObject *rtn_list = PyList_New(0);
    PyObject *item_tuple = PyTuple_New(2);
    PyObject * addr_entry = (PyObject *)NULL;
    PyObject * name_entry = (PyObject *)NULL;

    addr_entry = PyString_FromString( "addr" );
    int err = PyTuple_SetItem( item_tuple, 0, addr_entry );
    if (err) Py_XDECREF( item_tuple );

    name_entry = PyString_FromString( "name" );
    err = PyTuple_SetItem( item_tuple, 1, name_entry );
    if (err) Py_XDECREF( item_tuple );

    err = PyList_Append( rtn_list, item_tuple );
    Py_DECREF( item_tuple );


    return rtn_list;
}

/*
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
*/

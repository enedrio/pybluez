#ifndef __ble_h__
#define __ble_h__

PyObject *
bt_lescan(PyObject *self, PyObject *args);
PyDoc_STRVAR(bt_lescan_doc,
"connect_ex(address) -> errno\n\
\n\
This is like connect(address), but returns an error code (the errno value)\n\
instead of raising an exception when an error occurs.");


#endif /*__ble_h__*/

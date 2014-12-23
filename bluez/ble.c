#include "Python.h"
#include "ble.h"
#include "btmodule.h"
#include <port3.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <time.h>

#define EIR_NAME_SHORT              0x08  /* shortened local name */
#define EIR_NAME_COMPLETE           0x09  /* complete local name */

static PyObject * ble_exception(const char * message)
{
    PyErr_SetString(PyExc_RuntimeError, message);
    return NULL;
}

static void eir_parse_name(uint8_t *eir, size_t eir_len,
                        char *buf, size_t buf_len)
{
    size_t offset;

    offset = 0;
    while (offset < eir_len) {
        uint8_t field_len = eir[0];
        size_t name_len;

        /* Check for the end of EIR */
        if (field_len == 0)
            break;

        if (offset + field_len > eir_len)
            return;

        if(eir[1] == EIR_NAME_SHORT || eir[1] == EIR_NAME_COMPLETE) {
            name_len = field_len - 1;
            if (name_len > buf_len)
                return;

            memcpy(buf, &eir[2], name_len);
            return;
        }

        offset += field_len + 1;
        eir += field_len + 1;
    }
}

//TODO duplicated from btmodule.c
static int
internal_select(int dd, int writing, double sock_timeout)
{
    fd_set fds;
    struct timeval tv;
    int n;

    /* Nothing to do unless we're in timeout mode (not non-blocking) */
    if (sock_timeout <= 0.0)
        return 0;

    /* Guard against closed socket */
    if (dd < 0)
        return 0;

    /* Construct the arguments to select */
    tv.tv_sec = (int)sock_timeout;
    tv.tv_usec = (int)((sock_timeout - tv.tv_sec) * 1e6);
    FD_ZERO(&fds);
    FD_SET(dd, &fds);

    /* See if the socket is ready */
    if (writing)
        n = select(dd+1, NULL, &fds, NULL, &tv);
    else
        n = select(dd+1, &fds, NULL, NULL, &tv);
    if (n == 0)
        return 1;
    return 0;
}

static PyObject * print_advertising_devices(int dd, int duration)
{
    unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
    struct hci_filter nf, of;
    socklen_t olen;
    int len = 0, timeout, err;
    double totime = duration, selectto;
    clock_t start;
    PyObject *rtn_set = PySet_New(0);
    if(rtn_set == NULL) return NULL;


    olen = sizeof(of);
    if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0) {
        return ble_exception("Could not get socket options");
    }

    hci_filter_clear(&nf);
    hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
    hci_filter_set_event(EVT_LE_META_EVENT, &nf);

    if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
        return ble_exception("Could not set socket options");
    }

    start = clock();
    while (1) {
        evt_le_meta_event *meta;
        le_advertising_info *info;
        char addr[18];

        selectto = totime - ((clock() - start)/100.0);

        if(selectto <= 0) {
            goto done;
        }
        Py_BEGIN_ALLOW_THREADS
        timeout = internal_select(dd, 0, selectto);
        Py_END_ALLOW_THREADS
        if (!timeout) {
            len = read(dd, buf, sizeof(buf));
            if (errno == EINTR && (PyErr_CheckSignals() < 0)) {
                len = 0;
                goto done;
            }
        } else {
            goto done;
        }

        ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
        len -= (1 + HCI_EVENT_HDR_SIZE);

        meta = (void *) ptr;

        if (meta->subevent != 0x02) {
            goto done;
        }

        /* Ignoring multiple reports */
        info = (le_advertising_info *) (meta->data + 1);

        ba2str(&info->bdaddr, addr);

        PyObject *item_tuple = PyTuple_New(2);
        PyObject * addr_entry = (PyObject *)NULL;
        addr_entry = PyString_FromString( addr );
        err = PyTuple_SetItem( item_tuple, 0, addr_entry );
        if (err) {
            Py_XDECREF( item_tuple );
            Py_XDECREF( rtn_set );
            len = -1;
            goto done;
        }
        char name[30];
        memset(name, 0, sizeof(name));
        eir_parse_name(info->data, info->length,
                        name, sizeof(name) - 1);

        addr_entry = PyString_FromString( name );
        err = PyTuple_SetItem( item_tuple, 1, addr_entry );
        if (err) {
            Py_XDECREF( item_tuple );
            Py_XDECREF( rtn_set );
            len = -1;
            goto done;
        }
        err = PySet_Add( rtn_set, item_tuple );
        Py_DECREF( item_tuple );
        if (err) {
            Py_XDECREF( rtn_set );
            len = -1;
            goto done;
        }
    }

done:
    setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));

    if (len < 0) return ble_exception("Could not set socket options");

    return rtn_set;
}

static PyObject * cmd_lescan(int sock_fd, int duration)
{
    int err, dd = sock_fd;
    uint8_t own_type = 0x00;
    uint8_t scan_type = 0x01;
    uint8_t filter_policy = 0x00;
    uint16_t interval = htobs(0x0012);
    uint16_t window = htobs(0x0012);
    uint8_t filter_dup = 1;
    PyObject * ret = NULL;

    err = hci_le_set_scan_parameters(dd, scan_type, interval, window,
                        own_type, filter_policy, 10000);
    if (err < 0) {
        return ble_exception("Set scan parameters failed");
    }

    err = hci_le_set_scan_enable(dd, 0x01, filter_dup, 10000);
    if (err < 0) {
        return ble_exception("Enable scan failed");
    }

    ret = print_advertising_devices(dd, duration);

    if (ret == NULL) {
        return ble_exception("Could not receive advertising events");
    }

    err = hci_le_set_scan_enable(dd, 0x00, filter_dup, 10000);
    if (err < 0) {
        return ble_exception("Disable scan failed");
    }

    return ret;
}

PyObject *
bt_lescan(PyObject *self, PyObject *args, PyObject *kwds) {
    PySocketSockObject *socko = NULL;
    int duration = 8;
    static char *keywords[] = {"sock", "duration", 0};

    if( !PyArg_ParseTupleAndKeywords(args, kwds, "O|i", keywords,
                &socko, &duration) ) {
        return NULL;
    }

    return cmd_lescan(socko->sock_fd, duration);

}


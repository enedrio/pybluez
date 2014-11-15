#include "Python.h"
#include "ble.h"
#include <port3.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

PyObject *ble_error;

static volatile int signal_received = 0;

static void sigint_handler(int sig)
{
    //TODO handle signal the python way;)
    //signal_received = sig;
}

#define EIR_NAME_SHORT              0x08  /* shortened local name */
#define EIR_NAME_COMPLETE           0x09  /* complete local name */

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
            goto failed;

        switch (eir[1]) {
        case EIR_NAME_SHORT:
        case EIR_NAME_COMPLETE:
            name_len = field_len - 1;
            if (name_len > buf_len)
                goto failed;

            memcpy(buf, &eir[2], name_len);
            return;
        }

        offset += field_len + 1;
        eir += field_len + 1;
    }

failed:
    snprintf(buf, buf_len, "(unknown)");
}


static int print_advertising_devices(int dd, uint8_t filter_type)
{
    unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
    struct hci_filter nf, of;
    struct sigaction sa;
    socklen_t olen;
    int len;

    olen = sizeof(of);
    if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0) {
        printf("Could not get socket options\n");
        return -1;
    }

    hci_filter_clear(&nf);
    hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
    hci_filter_set_event(EVT_LE_META_EVENT, &nf);

    if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
        printf("Could not set socket options\n");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_NOCLDSTOP;
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);

    while (1) {
        evt_le_meta_event *meta;
        le_advertising_info *info;
        char addr[18];

        while ((len = read(dd, buf, sizeof(buf))) < 0) {
            if (errno == EINTR && signal_received == SIGINT) {
                len = 0;
                goto done;
            }

            if (errno == EAGAIN || errno == EINTR)
                continue;
            goto done;
        }

        ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
        len -= (1 + HCI_EVENT_HDR_SIZE);

        meta = (void *) ptr;

        if (meta->subevent != 0x02)
            goto done;

        /* Ignoring multiple reports */
        info = (le_advertising_info *) (meta->data + 1);
//        if (check_report_filter(filter_type, info)) {
            char name[30];

            memset(name, 0, sizeof(name));

            ba2str(&info->bdaddr, addr);
            eir_parse_name(info->data, info->length,
                            name, sizeof(name) - 1);

            printf("%s %s\n", addr, name);
//        }
    }

done:
    setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));

    if (len < 0)
        return -1;

    return 0;
}

static PyObject * ble_exception(const char * message)
{
    PyErr_SetString(PyExc_RuntimeError, message);
    return NULL;
}

static PyObject * cmd_lescan(int dev_id, int opt)
{
    int err, dd;
    uint8_t own_type = 0x00;
    uint8_t scan_type = 0x01;
    uint8_t filter_type = 'l';
    uint8_t filter_policy = 0x00;
    uint16_t interval = htobs(0x0010);
    uint16_t window = htobs(0x0010);
    uint8_t filter_dup = 1;

    switch (opt) {
    case 'p':
        own_type = 0x01; /* Random */
        break;
    case 'P':
        scan_type = 0x00; /* Passive */
        break;
    case 'w':
        filter_policy = 0x01; /* Whitelist */
        break;
    case 'd':
        interval = htobs(0x0012);
        window = htobs(0x0012);
        break;
    case 'D':
        filter_dup = 0x00;
        break;
    default:
        printf("error");
        return NULL;
    }

    if (dev_id < 0)
        dev_id = hci_get_route(NULL);

    dd = hci_open_dev(dev_id);
    if (dd < 0) {
        return ble_exception("Could not open device");
    }

    err = hci_le_set_scan_parameters(dd, scan_type, interval, window,
                        own_type, filter_policy, 10000);
    if (err < 0) {
        return ble_exception("Set scan parameters failed");
    }

    err = hci_le_set_scan_enable(dd, 0x01, filter_dup, 10000);
    if (err < 0) {
        return ble_exception("Enable scan failed");
    }

    err = print_advertising_devices(dd, filter_type);
    if (err < 0) {
        return ble_exception("Could not receive advertising events");
    }

    err = hci_le_set_scan_enable(dd, 0x00, filter_dup, 10000);
    if (err < 0) {
        return ble_exception("Disable scan failed");
    }

    hci_close_dev(dd);
    Py_RETURN_NONE;
}

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

    return cmd_lescan(-1, 'd');

    return rtn_list;
}


#include <Python.h>
#include "scs.h"

#define __UNUSED(x) (x = x)

static PyObject *scs_test(PyObject *self, PyObject *args);

static PyObject *g_scs_error;

static PyMethodDef g_scs_methods[] = {

    { "test", scs_test, METH_VARARGS, 
        "Run a test" },

    { NULL, NULL, 0, NULL }     /* sentinel */
};

PyMODINIT_FUNC initscs(void)
{
    PyObject *module;

    module = Py_InitModule("scs", g_scs_methods);
    if (module == NULL)
        goto err;
    
    g_scs_error = PyErr_NewException("scs.error", NULL, NULL);
    Py_INCREF(g_scs_error);
    PyModule_AddObject(module, "scs", g_scs_error);

err:
    return;
}

static PyObject *scs_test(PyObject *self, PyObject *args)
{
    __UNUSED(self);

#define COOKIE  "0123456789qwertyuiopasdfghjklzxcvbnm"
    scs_t *scs = NULL;
    uint8_t k[16] = { 'd', 'e', 'a', 'd', 'b', 'e', 'e', 'f' };
    uint8_t hk[20] = { 'D', 'E', 'A', 'D', 'B', 'E', 'E', 'F' };

    if (scs_init("tid", AES_128_CBC_HMAC_SHA1, k, hk, 1, 3600, &scs) != SCS_OK)
        goto err;

    if (scs_encode(scs, (uint8_t *) COOKIE, strlen(COOKIE)))
        goto err;

    scs_term(scs);

    return Py_BuildValue("s", "ok!!!");

err:
    PyErr_SetString(g_scs_error, "SCS error");
    if (scs)
        scs_term(scs);
    return NULL;
}

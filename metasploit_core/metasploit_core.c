#include "msf_interface.h"
#include <ruby.h>
#include <stdio.h>
#include <stdlib.h>

static int msf_initialized = 0;

// Initialize Ruby VM and Metasploit Framework
void msf_init() {
    if (msf_initialized) return;
    ruby_init();
    ruby_init_loadpath();
    rb_require("msf/core");
    rb_require("msf/core/exploit");
    rb_require("msf/core/payload");
    msf_initialized = 1;
    printf("[*] Metasploit Framework initialized.\n");
}

// Cleanup Ruby VM
void msf_cleanup() {
    if (!msf_initialized) return;
    ruby_finalize();
    msf_initialized = 0;
    printf("[*] Metasploit Framework cleaned up.\n");
}

// Select a module
int msf_use_module(const char* module_type, const char* module_name) {
    if (!msf_initialized) return -1;

    VALUE result = rb_eval_string_protect(
        "framework.modules['" module_type "/" module_name "']",
        NULL
    );

    if (NIL_P(result)) {
        msf_print_error("Failed to load module.");
        return -1;
    }
    printf("[*] Module %s/%s loaded.\n", module_type, module_name);
    return 0;
}

// Set an option
int msf_set_option(const char* option, const char* value) {
    if (!msf_initialized) return -1;

    char script[256];
    snprintf(script, sizeof(script),
             "module.datastore['%s'] = '%s'",
             option, value);

    rb_eval_string_protect(script, NULL);
    printf("[*] Option %s set to %s.\n", option, value);
    return 0;
}

// Set payload
int msf_set_payload(const char* payload) {
    return msf_set_option("payload", payload);
}

// Run exploit
int msf_run_exploit() {
    if (!msf_initialized) return -1;

    int error;
    rb_eval_string_protect("module.exploit", &error);

    if (error) {
        msf_print_error("Exploit failed.");
        return -1;
    }
    printf("[*] Exploit launched successfully.\n");
    return 0;
}

// Retrieve active sessions
int msf_get_active_sessions() {
    if (!msf_initialized) return -1;

    VALUE sessions = rb_eval_string("framework.sessions.length");
    return NUM2INT(sessions);
}

// Get session information
const char* msf_get_session_info(int session_id) {
    if (!msf_initialized) return NULL;

    char script[256];
    snprintf(script, sizeof(script),
             "framework.sessions[%d].info", session_id);

    VALUE info = rb_eval_string_protect(script, NULL);
    if (NIL_P(info)) {
        msf_print_error("Failed to retrieve session info.");
        return NULL;
    }
    return StringValueCStr(info);
}

// Print error message
void msf_print_error(const char* message) {
    fprintf(stderr, "[ERROR] %s\n", message);
}

/* Python CFFI Integration Example */
#ifdef PYTHON_WRAPPER
#include <Python.h>

static PyObject* py_msf_init(PyObject* self, PyObject* args) {
    msf_init();
    Py_RETURN_NONE;
}

static PyObject* py_msf_cleanup(PyObject* self, PyObject* args) {
    msf_cleanup();
    Py_RETURN_NONE;
}

static PyObject* py_msf_use_module(PyObject* self, PyObject* args) {
    const char* module_type;
    const char* module_name;
    if (!PyArg_ParseTuple(args, "ss", &module_type, &module_name))
        return NULL;
    return PyLong_FromLong(msf_use_module(module_type, module_name));
}

static PyObject* py_msf_set_option(PyObject* self, PyObject* args) {
    const char* option;
    const char* value;
    if (!PyArg_ParseTuple(args, "ss", &option, &value))
        return NULL;
    return PyLong_FromLong(msf_set_option(option, value));
}

static PyObject* py_msf_run_exploit(PyObject* self, PyObject* args) {
    return PyLong_FromLong(msf_run_exploit());
}

static PyMethodDef MsfMethods[] = {
    {"msf_init", py_msf_init, METH_NOARGS, "Initialize Metasploit Framework."},
    {"msf_cleanup", py_msf_cleanup, METH_NOARGS, "Cleanup Metasploit Framework."},
    {"msf_use_module", py_msf_use_module, METH_VARARGS, "Select a module."},
    {"msf_set_option", py_msf_set_option, METH_VARARGS, "Set module option."},
    {"msf_run_exploit", py_msf_run_exploit, METH_NOARGS, "Run exploit."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef msfmodule = {
    PyModuleDef_HEAD_INIT,
    "msf",
    NULL,
    -1,
    MsfMethods
};

PyMODINIT_FUNC PyInit_msf(void) {
    return PyModule_Create(&msfmodule);
}
#endif

#ifndef MSF_INTERFACE_H
#define MSF_INTERFACE_H

#ifdef __cplusplus
extern "C" {
#endif

// Initialize and cleanup the Metasploit framework
void msf_init();
void msf_cleanup();

// Module and Payload Management
int msf_use_module(const char* module_type, const char* module_name);
int msf_set_option(const char* option, const char* value);
int msf_set_payload(const char* payload);
int msf_run_exploit();

// Session Management
int msf_get_active_sessions();
const char* msf_get_session_info(int session_id);

// Utility
void msf_print_error(const char* message);

#ifdef PYTHON_WRAPPER
#include <Python.h>

PyObject* py_msf_init(PyObject* self, PyObject* args);
PyObject* py_msf_cleanup(PyObject* self, PyObject* args);
PyObject* py_msf_use_module(PyObject* self, PyObject* args);
PyObject* py_msf_set_option(PyObject* self, PyObject* args);
PyObject* py_msf_run_exploit(PyObject* self, PyObject* args);

PyMODINIT_FUNC PyInit_msf(void);
#endif

#ifdef __cplusplus
}
#endif

#endif // MSF_INTERFACE_H

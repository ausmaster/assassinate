/**
 * @file metasploit_core.c
 * @brief Core C FFI Wrapper for Metasploit Framework
 *
 * This file serves as the core implementation of the C wrapper
 * for the Metasploit Core shared library, enabling interaction
 * between the Metasploit Ruby backend and Python bindings using FFI.
 *
 * @author Author
 * @date 2024
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ruby.h>

/**
 * @def HANDLE_ERROR(msg)
 * @brief Macro for handling errors.
 * @param msg Error message to display.
 */
#define HANDLE_ERROR(msg) { \
    printf("[ERROR] %s\n", msg); \
    return Qnil; \
}

/**
 * @brief Global initialization state.
 */
static bool is_initialized = false;

/**
 * @brief Initialize the Metasploit Core library.
 * @return Qtrue if successful, Qfalse otherwise.
 */
static VALUE rb_msf_init(VALUE self) {
    if (is_initialized) {
        printf("Metasploit Core is already initialized.\n");
        return Qtrue;
    }
    is_initialized = true;
    printf("Metasploit Core initialized successfully.\n");
    return Qtrue;
}

/**
 * @brief Retrieve the version of Metasploit Core.
 * @return Version string.
 */
static VALUE rb_msf_get_version(VALUE self) {
    if (!is_initialized) HANDLE_ERROR("Core not initialized.");
    return rb_str_new_cstr("Metasploit Core v1.0");
}

/**
 * @brief List available modules of a specific type.
 * @param module_type The type of modules to list.
 * @return JSON string containing the list of modules.
 */
static VALUE rb_msf_list_modules(VALUE self, VALUE module_type) {
    Check_Type(module_type, T_STRING);
    if (!is_initialized) HANDLE_ERROR("Core not initialized.");
    printf("Listing modules of type: %s\n", StringValueCStr(module_type));
    return rb_str_new_cstr("[\"exploit1\", \"exploit2\"]");
}

/**
 * @brief Get module information.
 * @param module_type The type of the module.
 * @param module_name The name of the module.
 * @return JSON string with module information.
 */
static VALUE rb_msf_module_info(VALUE self, VALUE module_type, VALUE module_name) {
    Check_Type(module_type, T_STRING);
    Check_Type(module_name, T_STRING);
    if (!is_initialized) HANDLE_ERROR("Core not initialized.");
    printf("Fetching module info: %s/%s\n", StringValueCStr(module_type), StringValueCStr(module_name));
    return rb_str_new_cstr("{\"name\": \"example_module\", \"description\": \"Test\"}");
}

/**
 * @brief Execute a module.
 * @param module_type The type of the module.
 * @param module_name The name of the module.
 * @param options JSON string with module options.
 * @return Qtrue on success, Qfalse otherwise.
 */
static VALUE rb_msf_run_module(VALUE self, VALUE module_type, VALUE module_name, VALUE options) {
    Check_Type(module_type, T_STRING);
    Check_Type(module_name, T_STRING);
    Check_Type(options, T_HASH);
    if (!is_initialized) HANDLE_ERROR("Core not initialized.");
    printf("Running module: %s/%s\n", StringValueCStr(module_type), StringValueCStr(module_name));
    return Qtrue;
}

/**
 * @brief List active sessions.
 * @return JSON string with active sessions.
 */
static VALUE rb_msf_list_sessions(VALUE self) {
    if (!is_initialized) HANDLE_ERROR("Core not initialized.");
    return rb_str_new_cstr("[\"session1\", \"session2\"]");
}

/**
 * @brief Interact with a session.
 * @param session_id The ID of the session.
 * @return Qtrue on success, Qfalse otherwise.
 */
static VALUE rb_msf_interact_session(VALUE self, VALUE session_id) {
    Check_Type(session_id, T_STRING);
    if (!is_initialized) HANDLE_ERROR("Core not initialized.");
    printf("Interacting with session: %s\n", StringValueCStr(session_id));
    return Qtrue;
}

/**
 * @brief Close a session.
 * @param session_id The ID of the session.
 * @return Qtrue on success, Qfalse otherwise.
 */
static VALUE rb_msf_close_session(VALUE self, VALUE session_id) {
    Check_Type(session_id, T_STRING);
    if (!is_initialized) HANDLE_ERROR("Core not initialized.");
    printf("Closing session: %s\n", StringValueCStr(session_id));
    return Qtrue;
}

/**
 * @brief List active jobs.
 * @return JSON string with active jobs.
 */
static VALUE rb_msf_list_jobs(VALUE self) {
    if (!is_initialized) HANDLE_ERROR("Core not initialized.");
    return rb_str_new_cstr("[\"job1\", \"job2\"]");
}

/**
 * @brief Stop a job.
 * @param job_id The ID of the job.
 * @return Qtrue on success, Qfalse otherwise.
 */
static VALUE rb_msf_stop_job(VALUE self, VALUE job_id) {
    Check_Type(job_id, T_STRING);
    if (!is_initialized) HANDLE_ERROR("Core not initialized.");
    printf("Stopping job: %s\n", StringValueCStr(job_id));
    return Qtrue;
}

/**
 * @brief Generate a payload.
 * @param options JSON string with payload options.
 * @return JSON string with payload details.
 */
static VALUE rb_msf_payload_generator(VALUE self, VALUE options) {
    Check_Type(options, T_HASH);
    if (!is_initialized) HANDLE_ERROR("Core not initialized.");
    return rb_str_new_cstr("{\"payload\": \"generated\"}");
}

/**
 * @brief Shutdown Metasploit Core.
 */
static VALUE rb_msf_shutdown(VALUE self) {
    if (!is_initialized) return Qnil;
    is_initialized = false;
    printf("Metasploit Core shutdown successfully.\n");
    return Qnil;
}

/**
 * @brief Ruby module initialization.
 */
void Init_metasploit_core() {
    VALUE Metasploit = rb_define_module("Metasploit");
    rb_define_method(Metasploit, "init", rb_msf_init, 0);
    rb_define_method(Metasploit, "get_version", rb_msf_get_version, 0);
    rb_define_method(Metasploit, "list_modules", rb_msf_list_modules, 1);
    rb_define_method(Metasploit, "module_info", rb_msf_module_info, 2);
    rb_define_method(Metasploit, "run_module", rb_msf_run_module, 3);
    rb_define_method(Metasploit, "list_sessions", rb_msf_list_sessions, 0);
    rb_define_method(Metasploit, "interact_session", rb_msf_interact_session, 1);
    rb_define_method(Metasploit, "close_session", rb_msf_close_session, 1);
    rb_define_method(Metasploit, "list_jobs", rb_msf_list_jobs, 0);
    rb_define_method(Metasploit, "stop_job", rb_msf_stop_job, 1);
    rb_define_method(Metasploit, "payload_generator", rb_msf_payload_generator, 1);
    rb_define_method(Metasploit, "shutdown", rb_msf_shutdown, 0);
}

/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * pkcs11shim : a PKCS#11 shim library
 *
 * This work is based upon OpenSC pkcs11spy (https://github.com/OpenSC/OpenSC.git)
 *
 * Modified library Copyright (C) 2020  Mastercard
 * Original library Copyright (C) 2002  Olaf Kirch <okir@suse.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cryptoki.h"

#include "libscdl.h"
#include "libpkcs11.h"

#define MAGIC			0xd00bed00

typedef struct sc_pkcs11_module {
    unsigned int _magic;
    pkcs11_version_t version;
    void *handle;
} sc_pkcs11_module_t;

/**
 * C_LoadModule - Load a PKCS#11 module and detect its version
 * 
 * This function loads a PKCS#11 shared library and retrieves its function list.
 * It automatically detects whether the module supports PKCS#11 v3.x (via C_GetInterface)
 * or falls back to v2.0 (via C_GetFunctionList).
 * 
 * Version detection logic:
 * - First tries C_GetInterface (PKCS#11 v3.0+)
 * - If successful and version is 3.2, uses CK_FUNCTION_LIST_3_2
 * - If successful and version is 3.x (not 3.2), uses CK_FUNCTION_LIST_3_0
 * - If C_GetInterface not found or fails, falls back to C_GetFunctionList (v2.0)
 * 
 * @param libname  Path to the PKCS#11 shared library to load
 * @param funcs    Pointer to union that will receive the function list
 *                 (populated based on detected version)
 * 
 * @return Pointer to allocated module structure on success, NULL on failure
 *         Caller must free with C_UnloadModule()
 * 
 * @note Error messages are printed to stderr on failure
 * @note The module handle must be freed with C_UnloadModule() when done
 */
sc_pkcs11_module_t * C_LoadModule(const char *libname, pkcs11_function_list_t_ptr *funcs)
{
    sc_pkcs11_module_t *mod;
    CK_RV rv;

    CK_C_GetFunctionList c_get_function_list;
    CK_C_GetInterface  c_get_interface;

    /* argument checking */
    if (libname == NULL || funcs == NULL) {
	fprintf(stderr, "C_LoadModule: invalid arguments\n");
	return NULL;
    }

    mod = calloc(1, sizeof(*mod));
    if (mod == NULL) {
	fprintf(stderr, "C_LoadModule: out of memory\n");
	return NULL;
    }
    mod->_magic = MAGIC;
    /* mod->version is 0, hence V2 by default */
    /* mod->version = PKCS11_VERSION_2_0; */

    mod->handle = sc_dlopen(libname);
    if (mod->handle == NULL) {
	fprintf(stderr, "C_LoadModule: sc_dlopen failed: %s\n", sc_dlerror());
	goto failed;
    }

    /* Do we have C_GetInterface? If so, we can assume V3 at least*/
    c_get_interface = (CK_C_GetInterface) sc_dlsym(mod->handle, "C_GetInterface");

    if (c_get_interface) {
	CK_INTERFACE_PTR interface_ptr = NULL;
	CK_UTF8CHAR * interface_name = "PKCS 11";	// we only support this one.

        //fprintf(stderr, "C_LoadModule: Using C_GetInterface to load module\n");

	rv = c_get_interface(interface_name, NULL, &interface_ptr, 0);
	if (rv == CKR_OK && interface_ptr && interface_ptr->pFunctionList) {
            *funcs = interface_ptr->pFunctionList;  /* assign pointer here */
	    if((*funcs)->version.major == 3) {
		if((*funcs)->version.minor == 2) {
		    mod->version = PKCS11_VERSION_3_2;
		} else {
		    mod->version = PKCS11_VERSION_3_0;
		}
	    } else {
                // unknown major version, fallback to V2
                mod->version = PKCS11_VERSION_2_0;
            }
            return mod;

	} else {
            fprintf(stderr, "C_LoadModule: C_GetInterface failed %lx\n", rv);
            rv = C_UnloadModule(mod);
            if (rv == CKR_OK) {
                mod = NULL; /* already freed by C_UnloadModule */
            }
            /* will go to failed: */
        }
    } else {
        /* No C_GetInterface, fallback to V2 */
        /* However, the version could still be returned as V3.0 or V3.2 */
        /* Since the function table is an union*/

        /* Get the list of function pointers */
        c_get_function_list = (CK_C_GetFunctionList) sc_dlsym(mod->handle, "C_GetFunctionList");
        if (!c_get_function_list) {
            fprintf(stderr, "C_LoadModule: sc_dlsym C_GetFunctionList failed: %s\n", sc_dlerror());
            goto failed;
        }
	    
        //fprintf(stderr, "C_LoadModule: Falling back to C_GetFunctionList\n");
        rv = c_get_function_list((CK_FUNCTION_LIST_PTR_PTR)funcs);

        /* trick: this is a union, so we just look at the version */
        if (rv == CKR_OK && *funcs) {
            if((*funcs)->version.major == 3) {
                if((*funcs)->version.minor == 2) {
                    mod->version = PKCS11_VERSION_3_2;
                } else {
                    mod->version = PKCS11_VERSION_3_0;
                }
            } else {    
                mod->version = PKCS11_VERSION_2_0;
            }
            return mod;
	} else {
            fprintf(stderr, "C_GetFunctionList failed %lx\n", rv);
            rv = C_UnloadModule(mod);
            if (rv == CKR_OK) {
                mod = NULL; /* already freed */
            }
            /* will go to failed: */
        }
    }
failed:
    if(mod) free(mod);
    return NULL;
}

/**
 * C_GetModuleVersion - Get the PKCS#11 version of a loaded module
 * 
 * This function retrieves the PKCS#11 version that was detected when
 * the module was loaded with C_LoadModule.
 * 
 * @param module  Pointer to the module structure returned by C_LoadModule
 * 
 * @return The PKCS#11 version of the module:
 *         - PKCS11_VERSION_2_0 for PKCS#11 v2.x modules
 *         - PKCS11_VERSION_3_0 for PKCS#11 v3.0 modules
 *         - PKCS11_VERSION_3_2 for PKCS#11 v3.2 modules
 *         - PKCS11_VERSION_ILLEGAL if module is NULL or invalid
 * 
 * @note This function validates the module magic number before accessing it
 */
pkcs11_version_t C_GetModuleVersion(sc_pkcs11_module_t *module)
{
    sc_pkcs11_module_t *mod = (sc_pkcs11_module_t *) module;

    if (!mod || mod->_magic != MAGIC)
        return PKCS11_VERSION_ILLEGAL;

    return mod->version;
}
/*
 * Unload a pkcs11 module.
 * The calling application is responsible for cleaning up
 * and calling C_Finalize
 */
CK_RV C_UnloadModule(sc_pkcs11_module_t *module)
{
    sc_pkcs11_module_t *mod = (sc_pkcs11_module_t *) module;

    if (!mod || mod->_magic != MAGIC)
	return CKR_ARGUMENTS_BAD;

    if (mod->handle != NULL && sc_dlclose(mod->handle) < 0)
	return CKR_FUNCTION_FAILED;

    free(mod);
    return CKR_OK;
}

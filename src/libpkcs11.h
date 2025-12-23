/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * pkcs11shim : a PKCS#11 shim library
 *
 * libpkcs11.h: Function definitions for the PKCS#11 module loading minilibrary
 *
 * This work is based upon OpenSC pkcs11spy (https://github.com/OpenSC/OpenSC.git)
 *
 * Modified file Copyright (C) 2020  Mastercard
 * Original file Copyright (C) 2010  Martin Paljak <martin@paljak.pri.ee>
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

#ifndef __LIBPKCS11_H
#define __LIBPKCS11_H

#include "cryptoki.h"

typedef enum {
    PKCS11_VERSION_ILLEGAL = -1,
    PKCS11_VERSION_2_0 = 0,
    PKCS11_VERSION_3_0 = 1,
    PKCS11_VERSION_3_2 = 2,
} pkcs11_version_t;


/* since all function tables start with a CK_VERSION, */
/* we add it explicitly here so to map and access the version information */
/* directly without having to cast to a specific function table version */

typedef union {
    CK_VERSION version;
    CK_FUNCTION_LIST v2;
    CK_FUNCTION_LIST_3_0 v3_0;
    CK_FUNCTION_LIST_3_2 v3_2;
} pkcs11_function_list_t;

typedef pkcs11_function_list_t *pkcs11_function_list_t_ptr;

typedef struct sc_pkcs11_module sc_pkcs11_module_t;	// opaque module handle


sc_pkcs11_module_t* C_LoadModule(const char *name, pkcs11_function_list_t_ptr *funcs);
pkcs11_version_t C_GetModuleVersion(sc_pkcs11_module_t *module);
CK_RV C_UnloadModule(sc_pkcs11_module_t *module);

#endif /* __LIBPKCS11_H */

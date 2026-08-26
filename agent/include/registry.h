#ifndef REGISTRY_H
#define REGISTRY_H

#include <windows.h>

BOOL init_registry(void);
BOOL dump_registry_hives(HANDLE pipe);
BOOL dump_hive_files(HANDLE pipe);

#endif /* REGISTRY_H */

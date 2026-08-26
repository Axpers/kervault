#ifndef NTFS_H
#define NTFS_H

#include <windows.h>

/* Error stages written to *err on failure (returns 0):
 * 1=boot read  2=not NTFS  3=MFT map  4=mft_sz too big
 * 10+i=read dir MFT failed  20+i=name not found in dir
 * 30=read file MFT failed  31=file data read zero */
DWORD ntfs_read_hive(HANDLE hVolume, const wchar_t *hive_name, int hive_name_len,
                     BYTE *out, DWORD out_size,
                     BYTE *work, DWORD work_size,
                     DWORD *err);

#endif /* NTFS_H */

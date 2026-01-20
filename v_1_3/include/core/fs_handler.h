#ifndef FS_HANDLER_H
#define FS_HANDLER_H

#include <stdbool.h>
#include <stddef.h>

#include "http_common.h"

char *sanitize_path(const char *root, const char *uri);

const char *get_mime_type(const char *file);

// Sekarang fungsi ini bisa langsung mengenali MultipartPart
bool save_uploaded_file(MultipartPart *part, const char *destination_folder);

#endif
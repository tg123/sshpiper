#include <security/pam_appl.h>
#include <stdlib.h>

typedef struct {
    const char *str;
    int status;
} get_item_result;

get_item_result pam_get_item_string(pam_handle_t *handle, int type);
struct pam_conv* make_gopam_conv(void *goconv);


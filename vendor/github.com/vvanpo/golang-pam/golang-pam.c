#include <security/pam_types.h>
#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>
#include "_cgo_export.h"

/* Simplification of pam_get_item to remove type ambiguity.  Will never
   be called (promise) with a type that returns anything other than a string */
get_item_result pam_get_item_string(pam_handle_t *handle, int type) {
    get_item_result result;
    result.status = pam_get_item(handle, type, (const void **)&result.str);
    return result;
}

/* The universal conversation callback for gopam transactions.  appdata_ptr
   is always taken as a raw pointer to a Go-side pam.conversation object.
   In order to avoid nightmareish unsafe pointer math all over the Go
   implementation, this universal callback deals with memory allocation of
   response buffers, as well as unpacking and repackaging incoming messages
   and responses, calling a Go-side callback that handles each one on an
   individual basis. */
int gopam_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    int i, ok = 1;
    struct pam_response *responses = (struct pam_response*)malloc(sizeof(struct pam_response) * num_msg);
    memset(responses, 0, sizeof(struct pam_response) * num_msg);

    for(i = 0; i < num_msg; ++i) {
        const struct pam_message *m = msg[i];
        struct goPAMConv_return result = goPAMConv(m->msg_style, (char*)m->msg, appdata_ptr);
        if(result.r1 == PAM_SUCCESS)
            responses[i].resp = result.r0;
        else {
            ok = 0;
            break;
        }
    }

    if(ok) {
        *resp = responses;
        return PAM_SUCCESS;
    }

    /* In the case of failure PAM will never see these responses.  The
       resp strings that have been allocated by Go-side C.CString calls
       must be freed lest we leak them. */
    for(i = 0; i < num_msg; ++i)
        if(responses[i].resp != NULL)
            free(responses[i].resp);

    free(responses);
    return PAM_CONV_ERR;
}

/* This allocates a new pam_conv struct and fills in its fields:
   The conv function pointer always points to the universal gopam_conv.
   The appdata_ptr will be set to the incoming void* argument, which
   is always a Go-side *pam.conversation whose handler was given
   to pam.Start(). */
struct pam_conv* make_gopam_conv(void *goconv)
{
    struct pam_conv* conv = (struct pam_conv*)malloc(sizeof(struct pam_conv));
    conv->conv = gopam_conv;
    conv->appdata_ptr = goconv;
    return conv;
}


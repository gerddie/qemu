/*
 * implement the applets for the CAC card.
 *
 * This code is licensed under the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

#include <zlib.h>
#include "qemu-common.h"

#include "cac.h"
#include "vcard.h"
#include "vcard_emul.h"
#include "card_7816.h"

#define CERT_TAG_SIZE 8

/* private data for PKI applets */
typedef struct CACPKIAppletDataStruct {
    unsigned char *cert;
    int cert_len;
    unsigned char *cert_buffer;
    int cert_buffer_len;
    unsigned char *sign_buffer;
    int sign_buffer_len;
    VCardKey *key;
    unsigned char cert_tag[CERT_TAG_SIZE];
} CACPKIAppletData;

/*
 * CAC applet private data
 */
struct VCardAppletPrivateStruct {
    union {
        CACPKIAppletData pki_data;
        void *reserved;
    } u;
};

static VCardStatus
security_domain_process_apdu(VCard *card, VCardAPDU *apdu,
                                  VCardResponse **response)
{
    VCardStatus ret = VCARD_FAIL;

    switch (apdu->a_ins) {
    case VCARD7816_INS_GET_DATA: {
        /* TODO: check cla class */
        uint16_t tag = (apdu->a_p1 << 8) | apdu->a_p2;

        switch (tag) {
        case 0x0066:
            /* see H.2 Structure of Card Recognition Data */
            *response = vcard_response_new_hex(card,
                "66 31 "
                "73 2F "
                "06 07 2A 86 48 86 FC 6B 01 "
                "60 0C 06 0A 2A 86 48 86 FC 6B 02 02 01 01 "
                "63 09 06 07 2A 86 48 86 FC 6B 03 "
                "64 0B 06 09 2A 86 48 86 FC 6B 04 00 00 "
                "90 00", apdu->a_Le);

            return VCARD_DONE;
        case 0x9f7f:
            /* TODO: CPLC: */
            *response = vcard_response_new_hex(card,
                "9F 7F 2A 47 90 50 43 16 71 73 54 43 25 91 89 "
                "91 00 F5 F3 88 51 47 92 30 23 16 73 73 54 16 "
                "74 30 23 00 00 00 72 00 00 00 00 00 00 00 00 "
                "90 00", apdu->a_Le);
            return VCARD_DONE;
        default:
            *response =
                vcard_make_response(VCARD7816_STATUS_ERROR_DATA_NOT_FOUND);
            return VCARD_DONE;
        }
    }
    case VCARD7816_INS_SELECT_FILE:
    case VCARD7816_INS_GET_RESPONSE:
    case VCARD7816_INS_VERIFY:
        /* let the 7816 code handle these */
        ret = VCARD_NEXT;
        break;
    default:
        g_warning("%s not supported", G_STRLOC);
        *response =
          vcard_make_response(VCARD7816_STATUS_ERROR_COMMAND_NOT_SUPPORTED);
        ret = VCARD_DONE;
    }
    return ret;
}

static VCardStatus
ccc_process_apdu(VCard *card, VCardAPDU *apdu,
                 VCardResponse **response)
{
    VCardStatus ret = VCARD_FAIL;

    switch (apdu->a_ins) {
    case VCARD7816_INS_GET_DATA: {
        /* TODO: check cla class */
        uint16_t tag = (apdu->a_p1 << 8) | apdu->a_p2;
        g_debug("CCC get data tag: %x", tag);

        *response =
            vcard_make_response(VCARD7816_STATUS_ERROR_DATA_NOT_FOUND);
        return VCARD_DONE;
    }
    case VCARD7816_INS_SELECT_FILE:
    case VCARD7816_INS_GET_RESPONSE:
    case VCARD7816_INS_VERIFY:
        /* let the 7816 code handle these */
        ret = VCARD_NEXT;
        break;
    case CAC_READ_BUFFER: {
        /* new CAC call, go ahead and use the old version for now */

        int offset = (apdu->a_p1 << 8) + apdu->a_p2;
        int type = apdu->a_body[0];
        int len = apdu->a_body[1];

        g_debug("READ BUFFER type:%x offset:%x len:%x (card %p)",
                type, offset, len, card);
    }
    default:
        g_warning("%s not supported", G_STRLOC);
        *response =
            vcard_make_response(VCARD7816_STATUS_ERROR_COMMAND_NOT_SUPPORTED);
        ret = VCARD_DONE;
    }
    return ret;
}

/*
 * handle all the APDU's that are common to all CAC applets
 */
static VCardStatus
cac_common_process_apdu(VCard *card, VCardAPDU *apdu, VCardResponse **response)
{
    VCardStatus ret = VCARD_FAIL;

    switch (apdu->a_ins) {
    case VCARD7816_INS_SELECT_FILE:
        /* let the 7816 code handle applet switches */
        ret = VCARD_NEXT;
        break;
    case VCARD7816_INS_GET_RESPONSE:
    case VCARD7816_INS_VERIFY:
    case VCARD7816_INS_GET_DATA:
        /* let the 7816 code handle these */
        ret = VCARD_NEXT;
        break;
    case CAC_GET_PROPERTIES:
    case CAC_GET_ACR:
        /* skip these for now, this will probably be needed */
        *response = vcard_make_response(VCARD7816_STATUS_ERROR_P1_P2_INCORRECT);
        ret = VCARD_DONE;
        break;
    default:
        g_warning("%s not supported", G_STRLOC);
        *response = vcard_make_response(
            VCARD7816_STATUS_ERROR_COMMAND_NOT_SUPPORTED);
        ret = VCARD_DONE;
        break;
    }
    return ret;
}

/*
 *  reset the inter call state between applet selects
 */
static VCardStatus
cac_applet_pki_reset(VCard *card, int channel)
{
    VCardAppletPrivate *applet_private;
    CACPKIAppletData *pki_applet;
    applet_private = vcard_get_current_applet_private(card, channel);
    assert(applet_private);
    pki_applet = &(applet_private->u.pki_data);

    pki_applet->cert_buffer = NULL;
    g_free(pki_applet->sign_buffer);
    pki_applet->sign_buffer = NULL;
    pki_applet->cert_buffer_len = 0;
    pki_applet->sign_buffer_len = 0;
    return VCARD_DONE;
}

static VCardStatus
cac_applet_pki_process_apdu(VCard *card, VCardAPDU *apdu,
                            VCardResponse **response)
{
    CACPKIAppletData *pki_applet;
    VCardAppletPrivate *applet_private;
    int size, next;
    unsigned char *sign_buffer;
    bool retain_sign_buffer = FALSE;
    vcard_7816_status_t status;
    VCardStatus ret = VCARD_FAIL;

    applet_private = vcard_get_current_applet_private(card, apdu->a_channel);
    assert(applet_private);
    pki_applet = &(applet_private->u.pki_data);

    switch (apdu->a_ins) {
    case CAC_UPDATE_BUFFER:
        *response = vcard_make_response(
            VCARD7816_STATUS_ERROR_CONDITION_NOT_SATISFIED);
        ret = VCARD_DONE;
        break;
    case CAC_GET_CERTIFICATE:
        if ((apdu->a_p2 != 0) || (apdu->a_p1 != 0)) {
            *response = vcard_make_response(
                             VCARD7816_STATUS_ERROR_P1_P2_INCORRECT);
            break;
        }
        assert(pki_applet->cert != NULL);
        size = apdu->a_Le;
        if (pki_applet->cert_buffer == NULL) {
            pki_applet->cert_buffer = pki_applet->cert + 2;
            pki_applet->cert_buffer_len = pki_applet->cert_len - 2;
        }
        size = MIN(size, pki_applet->cert_buffer_len);
        next = MIN(255, pki_applet->cert_buffer_len - size);
        *response = vcard_response_new_bytes(
                        card, pki_applet->cert_buffer, size,
                        apdu->a_Le, next ?
                        VCARD7816_SW1_WARNING_CHANGE :
                        VCARD7816_SW1_SUCCESS,
                        next);
        pki_applet->cert_buffer += size;
        pki_applet->cert_buffer_len -= size;
        if ((*response == NULL) || (next == 0)) {
            pki_applet->cert_buffer = NULL;
        }
        if (*response == NULL) {
            *response = vcard_make_response(
                            VCARD7816_STATUS_EXC_ERROR_MEMORY_FAILURE);
        }
        ret = VCARD_DONE;
        break;
    case CAC_SIGN_DECRYPT:
        if (apdu->a_p2 != 0) {
            *response = vcard_make_response(
                             VCARD7816_STATUS_ERROR_P1_P2_INCORRECT);
            break;
        }
        size = apdu->a_Lc;

        sign_buffer = g_realloc(pki_applet->sign_buffer,
                                pki_applet->sign_buffer_len + size);
        g_return_val_if_fail(sign_buffer != NULL, VCARD_DONE);

        memcpy(sign_buffer+pki_applet->sign_buffer_len, apdu->a_body, size);
        size += pki_applet->sign_buffer_len;
        switch (apdu->a_p1) {
        case  0x80:
            /* p1 == 0x80 means we haven't yet sent the whole buffer, wait for
             * the rest */
            pki_applet->sign_buffer = sign_buffer;
            pki_applet->sign_buffer_len = size;
            *response = vcard_make_response(VCARD7816_STATUS_SUCCESS);
            retain_sign_buffer = TRUE;
            break;
        case 0x00:
            /* we now have the whole buffer, do the operation, result will be
             * in the sign_buffer */
            status = vcard_emul_rsa_op(card, pki_applet->key,
                                       sign_buffer, size);
            if (status != VCARD7816_STATUS_SUCCESS) {
                *response = vcard_make_response(status);
                break;
            }
            *response = vcard_response_new(card, sign_buffer, size, apdu->a_Le,
                                                     VCARD7816_STATUS_SUCCESS);
            if (*response == NULL) {
                *response = vcard_make_response(
                                VCARD7816_STATUS_EXC_ERROR_MEMORY_FAILURE);
            }
            break;
        default:
           *response = vcard_make_response(
                                VCARD7816_STATUS_ERROR_P1_P2_INCORRECT);
            break;
        }
        if (!retain_sign_buffer) {
            g_free(sign_buffer);
            pki_applet->sign_buffer = NULL;
            pki_applet->sign_buffer_len = 0;
        }
        ret = VCARD_DONE;
        break;
    case CAC_READ_BUFFER: {
        /* new CAC call, go ahead and use the old version for now */

        guint8 *buffer; /* FIXME: should be const */
        int buffer_len = -1;
        int offset = (apdu->a_p1 << 8) + apdu->a_p2;
        int type = apdu->a_body[0];
        int len = apdu->a_body[1];

        g_debug("READ BUFFER type:%x offset:%x len:%x (card %p)", type, offset, len, card);

        if (type == 1) {
            buffer = pki_applet->cert_tag;
            buffer_len = sizeof(pki_applet->cert_tag);
        } else if (type == 2) {
            /* select cert */
            buffer = pki_applet->cert;
            buffer_len = pki_applet->cert_len;
        }

        if (offset + len <= buffer_len) {
            *response =
                vcard_response_new_bytes(card, buffer + offset, len, apdu->a_Le,
                                         VCARD7816_SW1_SUCCESS, 0);
        }

        if (!*response) {
            g_warning("%s not supported", G_STRLOC);
            *response =
                vcard_make_response(VCARD7816_STATUS_ERROR_COMMAND_NOT_SUPPORTED);
        }
        ret = VCARD_DONE;
        break;
    }
    default:
        ret = cac_common_process_apdu(card, apdu, response);
        break;
    }
    return ret;
}


static VCardStatus
cac_applet_id_process_apdu(VCard *card, VCardAPDU *apdu,
                           VCardResponse **response)
{
    VCardStatus ret = VCARD_FAIL;

    switch (apdu->a_ins) {
    case CAC_TODO:
        *response = vcard_make_response(
                        VCARD7816_STATUS_SUCCESS);
        ret = VCARD_DONE;
        break;
    case CAC_UPDATE_BUFFER:
        *response = vcard_make_response(
                        VCARD7816_STATUS_ERROR_CONDITION_NOT_SATISFIED);
        ret = VCARD_DONE;
        break;
    case CAC_READ_BUFFER:
        /* new CAC call, go ahead and use the old version for now */
        /* TODO: implement */
        *response = vcard_make_response(
                        VCARD7816_STATUS_ERROR_COMMAND_NOT_SUPPORTED);
        ret = VCARD_DONE;
        break;
    default:
        ret = cac_common_process_apdu(card, apdu, response);
        break;
    }
    return ret;
}


/*
 * TODO: if we ever want to support general CAC middleware, we will need to
 * implement the various containers.
 */
static VCardStatus
cac_applet_container_process_apdu(VCard *card, VCardAPDU *apdu,
                                  VCardResponse **response)
{
    VCardStatus ret = VCARD_FAIL;

    switch (apdu->a_ins) {
    case CAC_READ_BUFFER:
    case CAC_UPDATE_BUFFER:
        g_warning("%s not supported", G_STRLOC);
        *response = vcard_make_response(
                        VCARD7816_STATUS_ERROR_COMMAND_NOT_SUPPORTED);
        ret = VCARD_DONE;
        break;
    default:
        ret = cac_common_process_apdu(card, apdu, response);
        break;
    }
    return ret;
}

/*
 * utilities for creating and destroying the private applet data
 */
static void
cac_delete_pki_applet_private(VCardAppletPrivate *applet_private)
{
    CACPKIAppletData *pki_applet_data;

    if (applet_private == NULL) {
        return;
    }
    pki_applet_data = &(applet_private->u.pki_data);
    g_free(pki_applet_data->cert);
    g_free(pki_applet_data->sign_buffer);
    if (pki_applet_data->key != NULL) {
        vcard_emul_delete_key(pki_applet_data->key);
    }
    g_free(applet_private);
}

static VCardAppletPrivate *
cac_new_pki_applet_private(const unsigned char *cert,
                           int cert_len, VCardKey *key)
{
    CACPKIAppletData *pki_applet_data;
    VCardAppletPrivate *applet_private;
    int zret;
    uLong zlen;
    char cert_tag[CERT_TAG_SIZE] = { CERT_TAG_SIZE - 2, 0x00,
                                     0x71, 0x01,
                                     0x70, 0xFF, 0x00, 0x00 };

    g_return_val_if_fail(cert_len < 0xffff, NULL);

    applet_private = g_new0(VCardAppletPrivate, 1);
    pki_applet_data = &(applet_private->u.pki_data);

    zlen = compressBound(cert_len);
    pki_applet_data->cert = (unsigned char *)g_malloc(zlen + 3);

    zret = compress(&pki_applet_data->cert[3], &zlen, cert, cert_len);
    if (zret != Z_OK) {
      g_warn_if_reached();
      g_free(pki_applet_data->cert);
      g_free(applet_private);
      return NULL;
    }

    pki_applet_data->cert[0] = (zlen + 1) & 0xff;
    pki_applet_data->cert[1] = (zlen + 1) >> 8;
    pki_applet_data->cert[2] = 1; /* compressed */
    pki_applet_data->cert_len = zlen + 3;

    memcpy(pki_applet_data->cert_tag, cert_tag, sizeof(cert_tag));
    pki_applet_data->cert_tag[6] = zlen & 0xff;
    pki_applet_data->cert_tag[7] = zlen >> 8;

    pki_applet_data->key = key;
    return applet_private;
}


/*
 * create a new cac applet which links to a given cert
 */
static VCardApplet *
cac_new_pki_applet(int i, const unsigned char *cert,
                   int cert_len, VCardKey *key)
{
    VCardAppletPrivate *applet_private;
    VCardApplet *applet;
    unsigned char pki_aid[] = { 0xa0, 0x00, 0x00, 0x00, 0x79, 0x01, 0x00 };
    int pki_aid_len = sizeof(pki_aid);

    pki_aid[pki_aid_len-1] = i;

    applet_private = cac_new_pki_applet_private(cert, cert_len, key);
    if (applet_private == NULL) {
        goto failure;
    }
    applet = vcard_new_applet(cac_applet_pki_process_apdu, cac_applet_pki_reset,
                              pki_aid, pki_aid_len);
    if (applet == NULL) {
        goto failure;
    }
    vcard_set_applet_private(applet, applet_private,
                             cac_delete_pki_applet_private);
    applet_private = NULL;

    return applet;

failure:
    if (applet_private != NULL) {
        cac_delete_pki_applet_private(applet_private);
    }
    return NULL;
}

/* TODO: A0 00 00 01 16 30 00 ? PIV RID GSC data model ? */
static unsigned char security_domain_aid[] = {
    0xa0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00 };
static unsigned char cac_default_container_aid[] = {
    0xa0, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00 };
static unsigned char cac_id_aid[] = {
    0xa0, 0x00, 0x00, 0x00, 0x79, 0x03, 0x00 };
static unsigned char cac_ccc_aid[] = {
    0xa0, 0x00, 0x00, 0x01, 0x16, 0xdb, 0x00 };
/*
 * Initialize the cac card. This is the only public function in this file. All
 * the rest are connected through function pointers.
 */
VCardStatus
cac_card_init(VReader *reader, VCard *card,
              const char *params,
              unsigned char * const *cert,
              int cert_len[],
              VCardKey *key[] /* adopt the keys*/,
              int cert_count)
{
    int i;
    VCardApplet *applet;

    /* CAC Cards are VM Cards */
    vcard_set_type(card, VCARD_VM);

    /* create one PKI applet for each cert */
    for (i = 0; i < cert_count; i++) {
        applet = cac_new_pki_applet(i, cert[i], cert_len[i], key[i]);
        if (applet == NULL) {
            goto failure;
        }
        vcard_add_applet(card, applet);
    }

    /* create a security domain */
    applet = vcard_new_applet(security_domain_process_apdu,
                              NULL, security_domain_aid,
                              sizeof(security_domain_aid));
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    /* create a CCC */
    applet = vcard_new_applet(ccc_process_apdu,
                              NULL, cac_ccc_aid,
                              sizeof(cac_ccc_aid));
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    /* create a default blank container applet */
    applet = vcard_new_applet(cac_applet_container_process_apdu,
                              NULL, cac_default_container_aid,
                              sizeof(cac_default_container_aid));
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    /* create a default blank container applet */
    applet = vcard_new_applet(cac_applet_id_process_apdu,
                              NULL, cac_id_aid,
                              sizeof(cac_id_aid));
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);
    return VCARD_DONE;

failure:
    return VCARD_FAIL;
}


/*
 * vfio-user defines
 *
 * Copyright (c) 2017 Red Hat, Inc.
 *
 * Authors:
 *  Marc-André Lureau <mlureau@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */
#ifndef VFIO_USER_H_
#define VFIO_USER_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
# define VFIO_USER_PACKED __attribute__((gcc_struct, packed))
#else
# define VFIO_USER_PACKED __attribute__((packed))
#endif

typedef enum vfio_user_req {
    VFIO_USER_REQ_NONE = 0,
    VFIO_USER_REQ_DEV_GET_INFO = 1,
    VFIO_USER_REQ_MAX
} vfio_user_req;

typedef struct vfio_user_msg {
    vfio_user_req req;
    uint32_t flags;
    uint32_t size; /* the following payload size */

    union {
        uint64_t u64;
    };
} VFIO_USER_PACKED vfio_user_msg;

#define VFIO_USER_HDR_SIZE offsetof(vfio_user_msg, u64)

#ifdef __cplusplus
}
#endif

#endif /* VFIO_USER_H_ */

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

#define VFIO_USER_MAX_FDS 16

typedef enum vfio_user_req {
    VFIO_USER_REQ_NONE = 0,
    VFIO_USER_REQ_DEV_GET_INFO = 1,
    VFIO_USER_REQ_DEV_GET_REGION_INFO = 2,
    VFIO_USER_REQ_DEV_GET_IRQ_INFO = 3,
    /* VFIO_USER_REQ_DEV_SET_IRQS = 4, */
    VFIO_USER_REQ_DEV_RESET = 5,
    /* VFIO_USER_REQ_DEV_GET_PCI_HOT_RESET_INFO = 6, */
    /* VFIO_USER_REQ_DEV_PCI_HOT_RESET = 7, */

    /* VFIO_USER_REQ_DEV_MMAP, */
    /* VFIO_USER_REQ_DEV_UNMMAP, */
    /* VFIO_USER_REQ_IOMMU_MAP_DMA, */
    /* VFIO_USER_REQ_IOMMU_UNMAP_DMA, */

    VFIO_USER_REQ_MAX
} vfio_user_req;

typedef struct vfio_user_msg {
    union {
        vfio_user_req request;
        int reply;
    };
    uint32_t flags;
    uint32_t size; /* the following payload size */

    union {
        uint8_t u8;
        uint32_t u32;
        uint64_t u64;
        struct vfio_device_info device_info;
        struct vfio_region_info region_info;
        struct vfio_irq_info irq_info;
    } payload;

    bool alloc_payload;
    int fd_num;
    int fds[VFIO_USER_MAX_FDS];
} VFIO_USER_PACKED vfio_user_msg;

#define VFIO_USER_HDR_SIZE offsetof(vfio_user_msg, payload.u8)

#ifdef __cplusplus
}
#endif

#endif /* VFIO_USER_H_ */

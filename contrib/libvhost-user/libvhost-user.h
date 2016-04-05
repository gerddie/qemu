/*
 * Vhost User library
 *
 * Copyright (c) 2016 Red Hat, Inc.
 *
 * Authors:
 *  Victor Kaplansky <victork@redhat.com>
 *  Marc-André Lureau <mlureau@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

#ifndef LIBVHOST_USER_H
#define LIBVHOST_USER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <linux/vhost.h>
#include "standard-headers/linux/virtio_ring.h"

/* Based on qemu/hw/virtio/vhost-user.c */
#define VHOST_USER_F_PROTOCOL_FEATURES 30
#define VHOST_LOG_PAGE 4096

#define VHOST_MAX_NR_VIRTQUEUE 8
#define VIRTQUEUE_MAX_SIZE 1024

#define VHOST_MEMORY_MAX_NREGIONS 8

enum VhostUserProtocolFeature {
    VHOST_USER_PROTOCOL_F_MQ = 0,
    VHOST_USER_PROTOCOL_F_LOG_SHMFD = 1,
    VHOST_USER_PROTOCOL_F_RARP = 2,

    VHOST_USER_PROTOCOL_F_MAX
};

#define VHOST_USER_PROTOCOL_FEATURE_MASK ((1 << VHOST_USER_PROTOCOL_F_MAX) - 1)

typedef enum VhostUserRequest {
    VHOST_USER_NONE = 0,
    VHOST_USER_GET_FEATURES = 1,
    VHOST_USER_SET_FEATURES = 2,
    VHOST_USER_SET_OWNER = 3,
    VHOST_USER_RESET_OWNER = 4,
    VHOST_USER_SET_MEM_TABLE = 5,
    VHOST_USER_SET_LOG_BASE = 6,
    VHOST_USER_SET_LOG_FD = 7,
    VHOST_USER_SET_VRING_NUM = 8,
    VHOST_USER_SET_VRING_ADDR = 9,
    VHOST_USER_SET_VRING_BASE = 10,
    VHOST_USER_GET_VRING_BASE = 11,
    VHOST_USER_SET_VRING_KICK = 12,
    VHOST_USER_SET_VRING_CALL = 13,
    VHOST_USER_SET_VRING_ERR = 14,
    VHOST_USER_GET_PROTOCOL_FEATURES = 15,
    VHOST_USER_SET_PROTOCOL_FEATURES = 16,
    VHOST_USER_GET_QUEUE_NUM = 17,
    VHOST_USER_SET_VRING_ENABLE = 18,
    VHOST_USER_SEND_RARP = 19,
    VHOST_USER_INPUT_GET_CONFIG = 20,
    VHOST_USER_MAX
} VhostUserRequest;

typedef struct VhostUserMemoryRegion {
    uint64_t guest_phys_addr;
    uint64_t memory_size;
    uint64_t userspace_addr;
    uint64_t mmap_offset;
} VhostUserMemoryRegion;

typedef struct VhostUserMemory {
    uint32_t nregions;
    uint32_t padding;
    VhostUserMemoryRegion regions[VHOST_MEMORY_MAX_NREGIONS];
} VhostUserMemory;

typedef struct VhostUserLog {
    uint64_t mmap_size;
    uint64_t mmap_offset;
} VhostUserLog;

#if defined(_WIN32)
# define VU_PACKED __attribute__((gcc_struct, packed))
#else
# define VU_PACKED __attribute__((packed))
#endif

typedef struct VhostUserMsg {
    VhostUserRequest request;

#define VHOST_USER_VERSION_MASK     (0x3)
#define VHOST_USER_REPLY_MASK       (0x1 << 2)
    uint32_t flags;
    uint32_t size; /* the following payload size */

    union {
#define VHOST_USER_VRING_IDX_MASK   (0xff)
#define VHOST_USER_VRING_NOFD_MASK  (0x1 << 8)
        uint64_t u64;
        struct vhost_vring_state state;
        struct vhost_vring_addr addr;
        VhostUserMemory memory;
        VhostUserLog log;
    } payload;

    int fds[VHOST_MEMORY_MAX_NREGIONS];
    int fd_num;
    uint8_t *data;
} VU_PACKED VhostUserMsg;

typedef struct VuDevRegion {
    /* Guest Physical address. */
    uint64_t gpa;
    /* Memory region size. */
    uint64_t size;
    /* QEMU virtual address (userspace). */
    uint64_t qva;
    /* Starting offset in our mmaped space. */
    uint64_t mmap_offset;
    /* Start address of mmaped space. */
    uint64_t mmap_addr;
} VuDevRegion;

typedef struct VuDev VuDev;

typedef uint64_t (*vu_get_features_cb) (VuDev *dev);
typedef void (*vu_set_features_cb) (VuDev *dev, uint64_t features);
typedef int (*vu_process_msg_cb) (VuDev *dev, VhostUserMsg *vmsg,
                                  int *do_reply);
typedef void (*vu_queue_set_started_cb) (VuDev *dev, int qidx, bool started);

typedef struct VuDevIface {
    vu_get_features_cb get_features;
    vu_set_features_cb set_features;
    vu_get_features_cb get_protocol_features;
    vu_set_features_cb set_protocol_features;
    vu_process_msg_cb process_msg;
    vu_queue_set_started_cb queue_set_started;
} VuDevIface;

typedef void (*vu_queue_handler_cb) (VuDev *dev, int qidx);

typedef struct VuRing {
    unsigned int num;
    struct vring_desc *desc;
    struct vring_avail *avail;
    struct vring_used *used;
    uint64_t log_guest_addr;
    uint32_t flags;
} VuRing;

typedef struct VuVirtq {
    VuRing vring;

    /* Next head to pop */
    uint16_t last_avail_idx;

    /* Last avail_idx read from VQ. */
    uint16_t shadow_avail_idx;

    uint16_t used_idx;

    /* Last used index value we have signalled on */
    uint16_t signalled_used;

    /* Last used index value we have signalled on */
    bool signalled_used_valid;

    /* Notification enabled? */
    bool notification;

    int inuse;

    vu_queue_handler_cb handler;

    int call_fd;
    int kick_fd;
    int err_fd;
    unsigned int enable;
    bool started;
} VuVirtq;

enum VuWatchCondtion {
    VU_WATCH_IN = 1 << 0,
    VU_WATCH_OUT = 1 << 1,
    VU_WATCH_PRI = 1 << 2,
    VU_WATCH_ERR = 1 << 3,
    VU_WATCH_HUP = 1 << 4,
};

typedef void (*vu_panic_cb) (VuDev *dev, const char *err);
typedef void (*vu_watch_cb) (VuDev *dev, int condition, void *data);
typedef void (*vu_add_watch_cb) (VuDev *dev, int fd, int condition,
                                 vu_watch_cb cb, void *data);
typedef void (*vu_remove_watch_cb) (VuDev *dev, int fd);

struct VuDev {
    int sock;
    uint32_t nregions;
    VuDevRegion regions[VHOST_MEMORY_MAX_NREGIONS];
    VuVirtq vq[VHOST_MAX_NR_VIRTQUEUE];
    int log_call_fd;
    uint64_t log_size;
    uint8_t *log_table;
    uint64_t features;
    uint64_t protocol_features;

    vu_add_watch_cb add_watch;
    vu_remove_watch_cb remove_watch;
    vu_panic_cb panic;
    const VuDevIface *iface;
};

typedef struct VuVirtqElement {
    unsigned int index;
    unsigned int out_num;
    unsigned int in_num;
    struct iovec *in_sg;
    struct iovec *out_sg;
} VuVirtqElement;

void vu_init(VuDev *dev,
             int socket,
             vu_panic_cb panic,
             vu_add_watch_cb add_watch,
             vu_remove_watch_cb remove_watch,
             const VuDevIface *iface);

void vu_deinit(VuDev *dev);

bool vu_dispatch(VuDev *dev);

void *vu_gpa_to_va(VuDev *dev, uint64_t guest_addr);

VuVirtq *vu_get_queue(VuDev *dev, int qidx);

void vu_set_queue_handler(VuDev *dev, VuVirtq *vq,
                          vu_queue_handler_cb handler);

void vu_queue_set_notification(VuDev *dev, VuVirtq *vq, int enable);

bool vu_queue_enabled(VuDev *dev, VuVirtq *vq);

int vu_queue_empty(VuDev *dev, VuVirtq *vq);

void vu_queue_notify(VuDev *dev, VuVirtq *vq);

void *vu_queue_pop(VuDev *dev, VuVirtq *vq, size_t sz);
void vu_queue_discard(VuDev *dev, VuVirtq *vq);

void vu_queue_fill(VuDev *dev, VuVirtq *vq,
                   const VuVirtqElement *elem,
                   unsigned int len, unsigned int idx);

void vu_queue_push(VuDev *dev, VuVirtq *vq,
                   const VuVirtqElement *elem, unsigned int len);

void vu_queue_flush(VuDev *dev, VuVirtq *vq, unsigned int count);

void vu_queue_get_avail_bytes(VuDev *vdev, VuVirtq *vq, unsigned int *in_bytes,
                              unsigned int *out_bytes,
                              unsigned max_in_bytes, unsigned max_out_bytes);

int vu_queue_avail_bytes(VuDev *dev, VuVirtq *vq, unsigned int in_bytes,
                         unsigned int out_bytes);

#endif /* LIBVHOST_USER_H */

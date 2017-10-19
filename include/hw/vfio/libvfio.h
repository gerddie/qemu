/*
 * libvfio library
 *
 * Copyright (c) 2017 Red Hat, Inc.
 *
 * Authors:
 *  Marc-André Lureau <mlureau@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */
#ifndef LIBVFIO_H_
#define LIBVFIO_H_

#include "qemu/osdep.h"
#include "chardev/char-fe.h"

#include <linux/vfio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef bool    libvfio_get_mem_fd_t                (void *ptr,
                                                     uint64_t *offset,
                                                     int *fd,
                                                     Error **errp);

typedef void *  libvfio_realloc_t                   (void *mem, size_t n_bytes);

typedef struct libvfio_ops libvfio_ops_t;

typedef struct libvfio {
    const libvfio_ops_t *ops;
    CharBackend *chr;
    libvfio_get_mem_fd_t *get_mem_fd;
    libvfio_realloc_t *realloc; /* realloc() by default */
} libvfio_t;

typedef struct libvfio_container {
    libvfio_t *vfio;
    int fd;
} libvfio_container_t;

typedef struct libvfio_group {
    libvfio_t *vfio;
    int fd;
    int groupid;
} libvfio_group_t;

typedef struct libvfio_dev {
    libvfio_t *vfio;
    int fd;
    int groupid;
    char *name;
} libvfio_dev_t;

bool            libvfio_init_host                   (libvfio_t *vfio,
                                                     int api_version,
                                                     Error **errp);
bool            libvfio_init_user                   (libvfio_t *vfio,
                                                     CharBackend *chr,
                                                     libvfio_get_mem_fd_t *get_mem_fd,
                                                     Error **errp);

bool            libvfio_init_container              (libvfio_t *vfio,
                                                     libvfio_container_t *container,
                                                     Error **errp);
void            libvfio_container_deinit            (libvfio_container_t *container);
bool            libvfio_container_check_extension   (libvfio_container_t *container,
                                                     int ext, Error **errp);
bool            libvfio_container_set_iommu         (libvfio_container_t *container,
                                                     int iommu_type,
                                                     Error **errp);
bool            libvfio_container_iommu_get_info    (libvfio_container_t *container,
                                                     struct vfio_iommu_type1_info *info,
                                                     Error **errp);
bool            libvfio_container_iommu_enable      (libvfio_container_t *container,
                                                     Error **errp);
bool            libvfio_container_iommu_map_dma     (libvfio_container_t *container,
                                                     uint64_t vaddr,
                                                     uint64_t iova,
                                                     uint64_t size,
                                                     uint32_t flags,
                                                     Error **errp);
bool            libvfio_container_iommu_unmap_dma   (libvfio_container_t *container,
                                                     uint64_t iova,
                                                     uint64_t size,
                                                     uint32_t flags,
                                                     Error **errp);
bool            libvfio_container_iommu_spapr_tce_get_info(libvfio_container_t *container,
                                                     struct vfio_iommu_spapr_tce_info *info,
                                                     Error **errp);
bool            libvfio_container_iommu_spapr_register_memory(libvfio_container_t *container,
                                                     uint64_t vaddr,
                                                     uint64_t size,
                                                     uint32_t flags,
                                                     Error **errp);
bool            libvfio_container_iommu_spapr_unregister_memory(libvfio_container_t *container,
                                                     uint64_t vaddr,
                                                     uint64_t size,
                                                     uint32_t flags,
                                                     Error **errp);
bool            libvfio_container_iommu_spapr_tce_create(libvfio_container_t *container,
                                                     uint32_t page_shift,
                                                     uint64_t window_size,
                                                     uint32_t levels,
                                                     uint32_t flags,
                                                     uint64_t *start_addr,
                                                     Error **errp);
bool            libvfio_container_iommu_spapr_tce_remove(libvfio_container_t *container,
                                                     uint64_t start_addr,
                                                     Error **errp);
bool            libvfio_container_eeh_pe_op         (libvfio_container_t *container,
                                                     uint32_t op,
                                                     Error **errp);

bool            libvfio_init_group                  (libvfio_t *vfio,
                                                     libvfio_group_t *group,
                                                     int groupid,
                                                     Error **errp);
bool            libvfio_group_get_host_fd           (libvfio_group_t *group,
                                                     int *fd);
void            libvfio_group_deinit                (libvfio_group_t *group);
bool            libvfio_group_set_container         (libvfio_group_t *group,
                                                     libvfio_container_t *container,
                                                     Error **errp);
bool            libvfio_group_unset_container       (libvfio_group_t *group,
                                                     libvfio_container_t *container,
                                                     Error **errp);
bool            libvfio_group_get_device            (libvfio_group_t *group,
                                                     libvfio_dev_t *dev,
                                                     Error **errp);

bool            libvfio_init_dev                    (libvfio_t *vfio,
                                                     libvfio_dev_t *dev,
                                                     const char *path,
                                                     Error **errp);
void            libvfio_dev_deinit                  (libvfio_dev_t *dev);
const char *    libvfio_dev_get_name                (libvfio_dev_t *dev);
int             libvfio_dev_get_groupid             (libvfio_dev_t *dev);
bool            libvfio_dev_reset                   (libvfio_dev_t *dev,
                                                     Error **errp);
bool            libvfio_dev_set_irq                 (libvfio_dev_t *dev,
                                                     uint32_t index,
                                                     uint32_t flags,
                                                     Error **errp);
bool            libvfio_dev_set_irq_fd              (libvfio_dev_t *dev,
                                                     uint32_t index,
                                                     int fd,
                                                     uint32_t flags,
                                                     Error **errp);
bool            libvfio_dev_set_irqs                (libvfio_dev_t *dev,
                                                     uint32_t index,
                                                     uint32_t start,
                                                     int *fds,
                                                     size_t nfd,
                                                     uint32_t flags,
                                                     Error **errp);
bool            libvfio_dev_get_irq_info            (libvfio_dev_t *dev,
                                                     uint32_t index,
                                                     struct vfio_irq_info *irq,
                                                     Error **errp);
bool            libvfio_dev_get_info                (libvfio_dev_t *dev,
                                                     struct vfio_device_info *info,
                                                     Error **errp);
bool            libvfio_dev_get_region_info         (libvfio_dev_t *dev,
                                                     uint32_t index,
                                                     struct vfio_region_info **info,
                                                     Error **errp);
bool            libvfio_dev_get_pci_hot_reset_info  (libvfio_dev_t *dev,
                                                     struct vfio_pci_hot_reset_info **info,
                                                     Error **errp);
bool            libvfio_dev_pci_hot_reset           (libvfio_dev_t *dev,
                                                     libvfio_group_t **groups,
                                                     size_t ngroups,
                                                     Error **errp);
ssize_t         libvfio_dev_write                   (libvfio_dev_t *dev,
                                                     const void *buf,
                                                     size_t size,
                                                     off_t offset,
                                                     Error **errp);
ssize_t         libvfio_dev_read                    (libvfio_dev_t *dev,
                                                     void *buf,
                                                     size_t size,
                                                     off_t offset,
                                                     Error **errp);
bool            libvfio_dev_read_all                (libvfio_dev_t *dev,
                                                     void *buf,
                                                     size_t size,
                                                     off_t offset,
                                                     size_t *bytes_read,
                                                     Error **errp);
void *          libvfio_dev_mmap                    (libvfio_dev_t *dev,
                                                     size_t length,
                                                     int prot,
                                                     int flags,
                                                     off_t offset,
                                                     Error **errp);
bool            libvfio_dev_unmmap                  (libvfio_dev_t *dev,
                                                     void *addr,
                                                     size_t length,
                                                     Error **errp);

#ifdef __cplusplus
}
#endif

#endif /* LIBVFIO_H_ */

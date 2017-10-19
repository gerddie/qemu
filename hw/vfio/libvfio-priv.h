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
#ifndef LIBVFIO_PRIV_H_
#define LIBVFIO_PRIV_H_

#include "hw/vfio/libvfio.h"
#include "qapi/error.h"

G_BEGIN_DECLS

#define ERR_PREFIX "libvfio error: "

struct libvfio_ops {
    bool (*init_container)                              (libvfio *vfio,
                                                         libvfio_container *container,
                                                         Error **errp);
    void (*container_deinit)                            (libvfio_container *container);
    bool (*container_check_extension)                   (libvfio_container *container,
                                                         int ext, Error **errp);
    bool (*container_set_iommu)                         (libvfio_container *container,
                                                         int iommu_type,
                                                         Error **errp);
    bool (*container_iommu_get_info)                    (libvfio_container *container,
                                                         struct vfio_iommu_type1_info *info,
                                                         Error **errp);
    bool (*container_iommu_enable)                      (libvfio_container *container,
                                                         Error **errp);
    bool (*container_iommu_map_dma)                     (libvfio_container *container,
                                                         uint64_t vaddr,
                                                         uint64_t iova,
                                                         uint64_t size,
                                                         uint32_t flags,
                                                         Error **errp);
    bool (*container_iommu_unmap_dma)                  (libvfio_container *container,
                                                        uint64_t iova,
                                                        uint64_t size,
                                                        uint32_t flags,
                                                        Error **errp);
    bool (*container_iommu_spapr_tce_get_info)         (libvfio_container *container,
                                                        struct vfio_iommu_spapr_tce_info *info,
                                                        Error **errp);
    bool (*container_iommu_spapr_register_memory)      (libvfio_container *container,
                                                        uint64_t vaddr,
                                                        uint64_t size,
                                                        uint32_t flags,
                                                        Error **errp);
    bool (*container_iommu_spapr_unregister_memory)    (libvfio_container *container,
                                                        uint64_t vaddr,
                                                        uint64_t size,
                                                        uint32_t flags,
                                                        Error **errp);
    bool (*container_iommu_spapr_tce_create)           (libvfio_container *container,
                                                        uint32_t page_shift,
                                                        uint64_t window_size,
                                                        uint32_t levels,
                                                        uint32_t flags,
                                                        uint64_t *start_addr,
                                                        Error **errp);
    bool (*container_iommu_spapr_tce_remove)           (libvfio_container *container,
                                                        uint64_t start_addr,
                                                        Error **errp);
    bool (*container_eeh_pe_op)                        (libvfio_container *container,
                                                        uint32_t op,
                                                        Error **errp);
    bool (*init_group)                                 (libvfio *vfio,
                                                        libvfio_group *group,
                                                        int groupid,
                                                        Error **errp);
    void (*group_deinit)                               (libvfio_group *group);
    bool (*group_get_device)                           (libvfio_group *group,
                                                        libvfio_dev *dev,
                                                        Error **errp);
    bool (*group_set_container)                        (libvfio_group *group,
                                                        libvfio_container *container,
                                                        Error **errp);
    bool (*group_unset_container)                      (libvfio_group *group,
                                                        libvfio_container *container,
                                                        Error **errp);
    bool (*init_dev)                                   (libvfio *vfio,
                                                        libvfio_dev *dev,
                                                        const char *path,
                                                        Error **errp);
    void (*dev_deinit)                                 (libvfio_dev *dev);
    bool (*dev_reset)                                  (libvfio_dev *dev,
                                                        Error **errp);
    bool (*dev_set_irqs)                               (libvfio_dev *dev,
                                                        uint32_t index,
                                                        uint32_t start,
                                                        int *fds,
                                                        size_t nfds,
                                                        uint32_t flags,
                                                        Error **errp);
    bool (*dev_get_irq_info)                           (libvfio_dev *dev,
                                                        uint32_t index,
                                                        struct vfio_irq_info *irq,
                                                        Error **errp);
    bool (*dev_get_info)                               (libvfio_dev *dev,
                                                        struct vfio_device_info *info,
                                                        Error **errp);
    bool (*dev_get_region_info)                        (libvfio_dev *dev,
                                                        uint32_t index,
                                                        struct vfio_region_info *info,
                                                        Error **errp);
    bool (*dev_get_pci_hot_reset_info)                 (libvfio_dev *dev,
                                                        struct vfio_pci_hot_reset_info *info,
                                                        Error **errp);
    bool (*dev_pci_hot_reset)                          (libvfio_dev *dev,
                                                        libvfio_group **groups,
                                                        size_t ngroups,
                                                        Error **errp);
    ssize_t (*dev_write)                               (libvfio_dev *dev,
                                                        const void *buf,
                                                        size_t size,
                                                        off_t offset,
                                                        Error **errp);
    ssize_t (*dev_read)                                (libvfio_dev *dev,
                                                        void *buf,
                                                        size_t size,
                                                        off_t offset,
                                                        Error **errp);
    void * (*dev_mmap)                                 (libvfio_dev *dev,
                                                        size_t length,
                                                        int prot,
                                                        int flags,
                                                        off_t offset,
                                                        Error **errp);
    bool (*dev_unmmap)                                 (libvfio_dev *dev,
                                                        void *addr,
                                                        size_t length,
                                                        Error **errp);
};

G_END_DECLS

#endif /* LIBVFIO_PRIV_H_ */

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
#include "libvfio-priv.h"

static bool
libvfio_user_init_container(libvfio *vfio, libvfio_container *container,
                            Error **errp)
{
    *container = (struct libvfio_container) {
        .vfio = vfio,
    };
    return true;
}

static void
libvfio_user_container_deinit(libvfio_container *container)
{
}

static bool
libvfio_user_container_check_extension(libvfio_container *container,
                                       int ext, Error **errp)
{
    return false;
}

static bool
libvfio_user_container_set_iommu(libvfio_container *container, int iommu_type,
                                 Error **errp)
{
    return false;
}

static bool
libvfio_user_container_iommu_get_info(libvfio_container *container,
                                      struct vfio_iommu_type1_info *info,
                                      Error **errp)
{
    return false;
}

static bool
libvfio_user_container_iommu_enable(libvfio_container *container, Error **errp)
{
    return false;
}

static bool
libvfio_user_container_iommu_map_dma(libvfio_container *container,
                                     uint64_t vaddr, uint64_t iova,
                                     uint64_t size, uint32_t flags,
                                     Error **errp)
{
    return false;
}

static bool
libvfio_user_container_iommu_unmap_dma(libvfio_container *container,
                                       uint64_t iova, uint64_t size,
                                       uint32_t flags, Error **errp)
{
    return false;
}

static bool
libvfio_user_container_iommu_spapr_tce_get_info(libvfio_container *container,
                                                struct vfio_iommu_spapr_tce_info *info,
                                                Error **errp)
{
    return false;
}

static bool
libvfio_user_container_iommu_spapr_register_memory(libvfio_container *container,
                                                   uint64_t vaddr,
                                                   uint64_t size,
                                                   uint32_t flags,
                                                   Error **errp)
{
    return false;
}

static bool
libvfio_user_container_iommu_spapr_unregister_memory(libvfio_container *container,
                                                     uint64_t vaddr,
                                                     uint64_t size,
                                                     uint32_t flags,
                                                     Error **errp)
{
    return false;
}

static bool
libvfio_user_container_iommu_spapr_tce_create(libvfio_container *container,
                                              uint32_t page_shift,
                                              uint64_t window_size,
                                              uint32_t levels,
                                              uint32_t flags,
                                              uint64_t *start_addr,
                                              Error **errp)
{
    return false;
}

static bool
libvfio_user_container_iommu_spapr_tce_remove(libvfio_container *container,
                                              uint64_t start_addr,
                                              Error **errp)
{
    return false;
}

static bool
libvfio_user_container_eeh_pe_op(libvfio_container *container,
                                 uint32_t op, Error **errp)
{
    return false;
}

static bool
libvfio_user_init_group(libvfio *vfio, libvfio_group *group,
                        int groupid, Error **errp)
{
    *group = (struct libvfio_group) {
        .vfio = vfio,
    };

    return true;
}

static void
libvfio_user_group_deinit(libvfio_group *group)
{
}

static bool
libvfio_user_group_get_device(libvfio_group *group,
                              libvfio_dev *dev, Error **errp)
{
    return false;
}

static bool
libvfio_user_group_set_container(libvfio_group *group,
                                 libvfio_container *container,
                                 Error **errp)
{
    return false;
}

static bool
libvfio_user_group_unset_container(libvfio_group *group,
                                   libvfio_container *container,
                                   Error **errp)
{
    return false;
}

static bool
libvfio_user_init_dev(libvfio *vfio, libvfio_dev *dev,
                      const char *path, Error **errp)
{
    /* XXX: could learn to lookup a specific device */
    return true;
}

static void
libvfio_user_dev_deinit(libvfio_dev *dev)
{
}

static bool
libvfio_user_dev_reset(libvfio_dev *dev, Error **errp)
{
    return false;
}

static bool
libvfio_user_dev_set_irqs(libvfio_dev *dev,
                          uint32_t index,
                          uint32_t start,
                          int *fds,
                          size_t nfds,
                          uint32_t flags,
                          Error **errp)
{
    return false;
}

static bool
libvfio_user_dev_get_irq_info(libvfio_dev *dev,
                              uint32_t index,
                              struct vfio_irq_info *irq,
                              Error **errp)
{
    return false;
}

static bool
libvfio_user_dev_get_info(libvfio_dev *dev,
                          struct vfio_device_info *info, Error **errp)
{
    return false;
}

static bool
libvfio_user_dev_get_region_info(libvfio_dev *dev, int index,
                                 struct vfio_region_info *info, Error **errp)
{
    return false;
}

static bool
libvfio_user_dev_get_pci_hot_reset_info(libvfio_dev *dev,
                                        struct vfio_pci_hot_reset_info *info,
                                        Error **errp)
{
    return false;
}

static bool
libvfio_user_dev_pci_hot_reset(libvfio_dev *dev,
                               libvfio_group **groups,
                               size_t ngroups,
                               Error **errp)
{
    return false;
}

static ssize_t
libvfio_user_dev_write(libvfio_dev *dev,
                       const void *buf, size_t size, off_t offset,
                       Error **errp)
{
    return -1;
}

static ssize_t
libvfio_user_dev_read(libvfio_dev *dev,
                      void *buf, size_t size, off_t offset,
                      Error **errp)
{
    return -1;
}

static void *
libvfio_user_dev_mmap(libvfio_dev *dev,
                      size_t length, int prot, int flags, off_t offset,
                      Error **errp)
{
    return MAP_FAILED;
}

static bool
libvfio_user_dev_unmmap(libvfio_dev *dev,
                        void *addr, size_t length, Error **errp)
{
    return false;
}

static libvfio_ops libvfio_user_ops = {
    .init_container = libvfio_user_init_container,
    .container_deinit = libvfio_user_container_deinit,
    .container_check_extension = libvfio_user_container_check_extension,
    /* .container_set_iommu = libvfio_user_container_set_iommu, */
    /* .container_iommu_get_info = libvfio_user_container_iommu_get_info, */
    /* .container_iommu_enable = libvfio_user_container_iommu_enable, */
    /* .container_iommu_map_dma = libvfio_user_container_iommu_map_dma, */
    /* .container_iommu_unmap_dma = libvfio_user_container_iommu_unmap_dma, */
    /* .container_iommu_spapr_tce_get_info = libvfio_user_container_iommu_spapr_tce_get_info, */
    /* .container_iommu_spapr_register_memory = libvfio_user_container_iommu_spapr_register_memory, */
    /* .container_iommu_spapr_unregister_memory = libvfio_user_container_iommu_spapr_unregister_memory, */
    /* .container_iommu_spapr_tce_create = libvfio_user_container_iommu_spapr_tce_create, */
    /* .container_iommu_spapr_tce_remove = libvfio_user_container_iommu_spapr_tce_remove, */
    /* .container_eeh_pe_op = libvfio_user_container_eeh_pe_op, */
    .init_group = libvfio_user_init_group,
    .group_deinit = libvfio_user_group_deinit,
    /* .group_set_container = libvfio_user_group_set_container, */
    /* .group_unset_container = libvfio_user_group_unset_container, */
    /* .group_get_device = libvfio_user_group_get_device, */
    .init_dev = libvfio_user_init_dev,
    .dev_deinit = libvfio_user_dev_deinit,
    /* .dev_reset = libvfio_user_dev_reset, */
    /* .dev_set_irqs = libvfio_user_dev_set_irqs, */
    /* .dev_get_irq_info = libvfio_user_dev_get_irq_info, */
    /* .dev_get_info = libvfio_user_dev_get_info, */
    /* .dev_get_region_info = libvfio_user_dev_get_region_info, */
    /* .dev_get_pci_hot_reset_info = libvfio_user_dev_get_pci_hot_reset_info, */
    /* .dev_pci_hot_reset = libvfio_user_dev_pci_hot_reset, */
    /* .dev_write = libvfio_user_dev_write, */
    /* .dev_read = libvfio_user_dev_read, */
    /* .dev_mmap = libvfio_user_dev_mmap, */
    /* .dev_unmmap = libvfio_user_dev_unmmap, */
};

bool
libvfio_init_user(libvfio *vfio, CharBackend *chr, Error **errp)
{
    assert(vfio);
    assert(chr);

    *vfio = (struct libvfio) {
        .chr = chr,
        .ops = &libvfio_user_ops,
    };

    return true;
}

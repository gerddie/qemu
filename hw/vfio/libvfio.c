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
#include <sys/ioctl.h>

#define LIBVFIO_CALL(vfio, miss, op, ...) ({                    \
    typeof(miss) _ret = (miss);                                 \
    assert(vfio);                                               \
    assert(vfio->ops);                                          \
    g_debug(G_STRINGIFY(op));                                   \
    if (!vfio->ops->op) {                                       \
        error_setg(errp, ERR_PREFIX "'%s' op not implemented",  \
                   G_STRINGIFY(op));                            \
    } else {                                                    \
        _ret = (vfio)->ops->op(__VA_ARGS__);                    \
    }                                                           \
    _ret;                                                       \
})

#define LIBVFIO_VOID_CALL(vfio, op, ...) ({     \
    assert(vfio);                               \
    assert(vfio->ops);                          \
    assert(vfio->ops->op);                      \
    (vfio)->ops->op(__VA_ARGS__);               \
})

bool
libvfio_init_container(libvfio *vfio, libvfio_container *container,
                       Error **errp)
{
    assert(vfio);
    assert(container);

    *container = (struct libvfio_container) { .fd = -1 };

    return LIBVFIO_CALL(vfio, false,
                        init_container, vfio, container, errp);
}

void
libvfio_container_deinit(libvfio_container *container)
{
    assert(container);

    if (!container->vfio) {
        return;
    }

    LIBVFIO_VOID_CALL(container->vfio,
                      container_deinit, container);
    container->vfio = NULL;
}

bool
libvfio_container_check_extension(libvfio_container *container,
                                  int ext, Error **errp)
{
    assert(container);

    return LIBVFIO_CALL(container->vfio, false,
                        container_check_extension, container, ext, errp);
}

bool
libvfio_container_set_iommu(libvfio_container *container, int iommu_type,
                            Error **errp)
{
    assert(container);

    return LIBVFIO_CALL(container->vfio, false,
                        container_set_iommu, container, iommu_type, errp);
}

bool
libvfio_container_iommu_get_info(libvfio_container *container,
                                 struct vfio_iommu_type1_info *info,
                                 Error **errp)
{
    assert(container);
    assert(info);

    return LIBVFIO_CALL(container->vfio, false,
                        container_iommu_get_info, container, info, errp);
}

bool
libvfio_container_iommu_enable(libvfio_container *container, Error **errp)
{
    assert(container);

    return LIBVFIO_CALL(container->vfio, false,
                        container_iommu_enable, container, errp);
}

bool
libvfio_container_iommu_map_dma(libvfio_container *container,
                                uint64_t vaddr, uint64_t iova,
                                uint64_t size, uint32_t flags,
                                Error **errp)
{
    assert(container);

    return LIBVFIO_CALL(container->vfio, false,
                        container_iommu_map_dma, container,
                        vaddr, iova, size, flags, errp);
}

bool
libvfio_container_iommu_unmap_dma(libvfio_container *container,
                                  uint64_t iova, uint64_t size,
                                  uint32_t flags, Error **errp)
{
    assert(container);

    return LIBVFIO_CALL(container->vfio, false,
                        container_iommu_unmap_dma, container,
                        iova, size, flags, errp);
}

bool
libvfio_container_iommu_spapr_tce_get_info(libvfio_container *container,
                                         struct vfio_iommu_spapr_tce_info *info,
                                         Error **errp)
{
    assert(container);
    assert(info);

    return LIBVFIO_CALL(container->vfio, false,
                        container_iommu_spapr_tce_get_info,
                        container, info, errp);
}

bool
libvfio_container_iommu_spapr_register_memory(libvfio_container *container,
                                              uint64_t vaddr,
                                              uint64_t size,
                                              uint32_t flags,
                                              Error **errp)
{
    assert(container);

    return LIBVFIO_CALL(container->vfio, false,
                        container_iommu_spapr_register_memory,
                        container, vaddr, size, flags, errp);
}

bool
libvfio_container_iommu_spapr_unregister_memory(libvfio_container *container,
                                                uint64_t vaddr,
                                                uint64_t size,
                                                uint32_t flags,
                                                Error **errp)
{
    assert(container);

    return LIBVFIO_CALL(container->vfio, false,
                        container_iommu_spapr_unregister_memory,
                        container, vaddr, size, flags, errp);
}

bool
libvfio_container_iommu_spapr_tce_create(libvfio_container *container,
                                         uint32_t page_shift,
                                         uint64_t window_size,
                                         uint32_t levels,
                                         uint32_t flags,
                                         uint64_t *start_addr,
                                         Error **errp)
{
    assert(container);
    assert(start_addr);

    return LIBVFIO_CALL(container->vfio, false,
                        container_iommu_spapr_tce_create,
                        container, page_shift, window_size, levels, flags,
                        start_addr, errp);
}

bool
libvfio_container_iommu_spapr_tce_remove(libvfio_container *container,
                                         uint64_t start_addr,
                                         Error **errp)
{
    assert(container);

    return LIBVFIO_CALL(container->vfio, false,
                        container_iommu_spapr_tce_remove,
                        container, start_addr, errp);
}

bool
libvfio_container_eeh_pe_op(libvfio_container *container,
                            uint32_t op, Error **errp)
{
    assert(container);

    return LIBVFIO_CALL(container->vfio, false,
                        container_eeh_pe_op, container, op, errp);
}

bool
libvfio_init_group(libvfio *vfio, libvfio_group *group,
                   int groupid, Error **errp)
{
    assert(vfio);
    assert(group);

    *group = (struct libvfio_group) { .fd = -1 };

    return LIBVFIO_CALL(vfio, false,
                        init_group, vfio, group, groupid, errp);
}

bool
libvfio_group_get_host_fd(libvfio_group *group,
                          int *fd)
{
    assert(group);
    assert(group->vfio);
    assert(fd);

    if (group->vfio->chr) {
        return false;
    }

    *fd = group->fd;
    return true;
}

void
libvfio_group_deinit(libvfio_group *group)
{
    assert(group);

    if (!group->vfio) {
        return;
    }

    LIBVFIO_VOID_CALL(group->vfio, group_deinit, group);

    group->vfio = NULL;
}

bool
libvfio_group_get_device(libvfio_group *group, libvfio_dev *dev, Error **errp)
{
    assert(group);
    assert(dev);

    return LIBVFIO_CALL(group->vfio, false,
                        group_get_device, group, dev, errp);
}

bool
libvfio_group_set_container(libvfio_group *group, libvfio_container *container,
                            Error **errp)
{
    assert(group);
    assert(container);

    return LIBVFIO_CALL(group->vfio, false,
                        group_set_container, group, container, errp);
}

bool
libvfio_group_unset_container(libvfio_group *group, libvfio_container *container,
                              Error **errp)
{
    assert(group);
    assert(container);

    return LIBVFIO_CALL(group->vfio, false,
                        group_unset_container, group, container, errp);
}

bool
libvfio_init_dev(libvfio *vfio, libvfio_dev *dev,
                 const char *path, Error **errp)
{
    assert(vfio);
    assert(dev);

    *dev = (struct libvfio_dev) { .fd = -1 };

    return LIBVFIO_CALL(vfio, false,
                        init_dev, vfio, dev, path, errp);
}

void
libvfio_dev_deinit(libvfio_dev *dev)
{
    if (!dev->vfio) {
        return;
    }

    LIBVFIO_VOID_CALL(dev->vfio, dev_deinit, dev);
    dev->vfio = NULL;
}

const char *
libvfio_dev_get_name(libvfio_dev *dev)
{
    assert(dev);

    return dev->name;
}

int
libvfio_dev_get_groupid(libvfio_dev *dev)
{
    assert(dev);

    return dev->groupid;
}

bool
libvfio_dev_reset(libvfio_dev *dev, Error **errp)
{
    assert(dev);

    return LIBVFIO_CALL(dev->vfio, false,
                        dev_reset, dev, errp);
}

bool
libvfio_dev_set_irqs(libvfio_dev *dev,
                     uint32_t index,
                     uint32_t start,
                     int *fds,
                     size_t nfds,
                     uint32_t flags,
                     Error **errp)
{
    assert(dev);

    return LIBVFIO_CALL(dev->vfio, false,
                        dev_set_irqs,
                        dev, index, start, fds, nfds, flags, errp);
}

bool
libvfio_dev_set_irq_fd(libvfio_dev *dev,
                       uint32_t index,
                       int fd,
                       uint32_t flags,
                       Error **errp)
{
    return libvfio_dev_set_irqs(dev, index, 0,
                                &fd, 1, flags, errp);
}

bool
libvfio_dev_set_irq(libvfio_dev *dev,
                    uint32_t index,
                    uint32_t flags,
                    Error **errp)
{
    return libvfio_dev_set_irqs(dev, index, 0,
                                NULL, 0, flags, errp);
}

bool
libvfio_dev_get_irq_info(libvfio_dev *dev,
                         uint32_t index,
                         struct vfio_irq_info *irq,
                         Error **errp)
{
    assert(dev);
    assert(irq);

    return LIBVFIO_CALL(dev->vfio, false,
                        dev_get_irq_info, dev, index, irq, errp);
}

bool
libvfio_dev_get_info(libvfio_dev *dev,
                     struct vfio_device_info *info, Error **errp)
{
    assert(dev);
    assert(info);

    return LIBVFIO_CALL(dev->vfio, false,
                        dev_get_info, dev, info, errp);
}

bool
libvfio_dev_get_region_info(libvfio_dev *dev, int index,
                            struct vfio_region_info *info, Error **errp)
{
    assert(dev);
    assert(info);
    assert(info->argsz >= sizeof(*info));

    return LIBVFIO_CALL(dev->vfio, false,
                        dev_get_region_info, dev, index, info, errp);
}

bool
libvfio_dev_get_pci_hot_reset_info(libvfio_dev *dev,
                                   struct vfio_pci_hot_reset_info *info,
                                   Error **errp)
{
    assert(dev);
    assert(info);
    assert(info->argsz >= sizeof(*info));

    return LIBVFIO_CALL(dev->vfio, false,
                        dev_get_pci_hot_reset_info, dev, info, errp);
}

bool
libvfio_dev_pci_hot_reset(libvfio_dev *dev,
                          libvfio_group **groups,
                          size_t ngroups,
                          Error **errp)
{
    assert(dev);
    assert(ngroups == 0 || groups);

    return LIBVFIO_CALL(dev->vfio, false,
                        dev_pci_hot_reset, dev, groups, ngroups, errp);
}

ssize_t
libvfio_dev_write(libvfio_dev *dev,
                  const void *buf, size_t size, off_t offset,
                  Error **errp)
{
    assert(dev);
    assert(size == 0 || buf);

    return LIBVFIO_CALL(dev->vfio, -1,
                        dev_write, dev, buf, size, offset, errp);
}

ssize_t
libvfio_dev_read(libvfio_dev *dev,
                 void *buf, size_t size, off_t offset,
                 Error **errp)
{
    assert(dev);
    assert(size == 0 || buf);

    return LIBVFIO_CALL(dev->vfio, -1,
                        dev_read, dev, buf, size, offset, errp);
}

bool
libvfio_dev_read_all(libvfio_dev *dev,
                     void *buf, size_t size, off_t offset,
                     size_t *bytes_read, Error **errp)
{
    size_t count = 0;

    while (size) {
        ssize_t ret = libvfio_dev_read(dev, buf, size, offset, errp);
        if (ret < 0) {
            return false;
        } else if (ret == 0) {
            break;
        }

        size -= ret;
        buf += ret;
        offset += ret;
        count += ret;
    }

    if (bytes_read) {
        *bytes_read = count;
    }

    return true;
}

void *
libvfio_dev_mmap(libvfio_dev *dev,
                 size_t length, int prot, int flags, off_t offset,
                 Error **errp)
{
    assert(dev);

    return LIBVFIO_CALL(dev->vfio, MAP_FAILED,
                        dev_mmap, dev, length, prot, flags, offset, errp);
}

bool
libvfio_dev_unmmap(libvfio_dev *dev, void *addr, size_t length, Error **errp)
{
    assert(dev);

    return LIBVFIO_CALL(dev->vfio, false,
                        dev_unmmap, dev, addr, length, errp);
}

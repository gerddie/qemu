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
#include "vfio-user.h"

static bool
libvfio_user_write(libvfio_t *vfio, vfio_user_msg *msg, Error **errp)
{
    int size = VFIO_USER_HDR_SIZE + msg->size;
    int ret = qemu_chr_fe_write_all(vfio->chr, (uint8_t *)msg, size);

    if (ret != size) {
        error_setg(errp, "failed to write %d bytes, wrote %d", size, ret);
        return false;
    }

    return true;
}

static bool
libvfio_user_read_hdr(libvfio_t *vfio, vfio_user_msg *msg, Error **errp)
{
    int size = VFIO_USER_HDR_SIZE;
    int ret = qemu_chr_fe_read_all(vfio->chr, (uint8_t *)msg, size);

    if (ret != size) {
        error_setg(errp, "failed to read %d bytes, read %d", size, ret);
        return false;
    }

    return true;
}

static bool
libvfio_user_read(libvfio_t *vfio, vfio_user_msg *msg, Error **errp)
{
    int ret;

    if (!libvfio_user_read_hdr(vfio, msg, errp)) {
        return false;
    }

    if (msg->size > sizeof(msg->payload)) {
        error_setg(errp, "invalid payload size %" PRIu32, msg->size);
        return false;
    }

    ret = qemu_chr_fe_read_all(vfio->chr, &msg->payload.u8, msg->size);
    if (ret != msg->size) {
        error_setg(errp, "failed to read %d bytes, read %d", msg->size, ret);
        return false;
    }

    return true;
}

static bool
libvfio_user_read_payload(libvfio_t *vfio, void *payload,
                          size_t size, Error **errp)
{
    int ret = qemu_chr_fe_read_all(vfio->chr, payload, size);

    if (ret != size) {
        error_setg(errp, "failed to read %zu bytes, read %d", size, ret);
        return false;
    }

    return true;
}

static bool
libvfio_user_init_container(libvfio_t *vfio, libvfio_container_t *container,
                            Error **errp)
{
    *container = (struct libvfio_container) {
        .vfio = vfio,
    };
    return true;
}

static void
libvfio_user_container_deinit(libvfio_container_t *container)
{
}

static bool
libvfio_user_container_check_extension(libvfio_container_t *container,
                                       int ext, Error **errp)
{
    if (ext == VFIO_TYPE1_IOMMU || VFIO_TYPE1v2_IOMMU) {
        return true;
    }

    return false;
}

static bool
libvfio_user_container_set_iommu(libvfio_container_t *container, int iommu_type,
                                 Error **errp)
{
    return true;
}

static bool
libvfio_user_container_iommu_get_info(libvfio_container_t *container,
                                      struct vfio_iommu_type1_info *info,
                                      Error **errp)
{
    *info = (struct vfio_iommu_type1_info) {
        .flags = VFIO_IOMMU_INFO_PGSIZES,
        .iova_pgsizes = 4096,
    };
    return false;
}

static bool
libvfio_user_container_iommu_map_dma(libvfio_container_t *container,
                                     uint64_t vaddr, uint64_t iova,
                                     uint64_t size, uint32_t flags,
                                     Error **errp)
{
    uint64_t offset;
    int fd;

    g_debug("map_dma vaddr:0x%" PRIx64 " iova:0x%" PRIx64
            " size:0x%" PRIx64 " flags:0x%" PRIx32,
            vaddr, iova, size, flags);

    if (!container->vfio->get_mem_fd((void *)(uintptr_t)vaddr,
                                     &offset, &fd, errp)) {
        return false;
    }
    g_debug("map_dma fd:%d, offset:0x%" PRIx64, fd, offset);

    return true;
}

static bool
libvfio_user_container_iommu_unmap_dma(libvfio_container_t *container,
                                       uint64_t iova, uint64_t size,
                                       uint32_t flags, Error **errp)
{
    g_debug("unmap_dma iova:0x%" PRIx64 " size:0x%" PRIx64 " flags:0x%" PRIx32,
            iova, size, flags);

    return true;
}

static bool
libvfio_user_init_group(libvfio_t *vfio, libvfio_group *group,
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
    /* XXX: could learn to lookup a specific device */
    return true;
}

static bool
libvfio_user_group_set_container(libvfio_group *group,
                                 libvfio_container_t *container,
                                 Error **errp)
{
    return true;
}

static bool
libvfio_user_group_unset_container(libvfio_group *group,
                                   libvfio_container_t *container,
                                   Error **errp)
{
    return true;
}

static bool
libvfio_user_init_dev(libvfio_t *vfio, libvfio_dev *dev,
                      const char *path, Error **errp)
{
    /* XXX: could learn to lookup a specific device */
    /* XXX: get device name */
    *dev = (struct libvfio_dev) {
        .name = g_strdup("vfio-user device"),
        .vfio = vfio,
    };

    return true;
}

static void
libvfio_user_dev_deinit(libvfio_dev *dev)
{
}

static bool
libvfio_user_dev_reset(libvfio_dev *dev, Error **errp)
{
    int ret = 0;

    if (ret < 0) {
        error_setg_errno(errp, errno, "failed to rest");
        return false;
    }

    return true;
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
    int ret = 0;

    if (ret < 0) {
        error_setg_errno(errp, -ret, "failed to set irqs");
        return false;
    }

    return true;
}

static bool
libvfio_user_dev_get_irq_info(libvfio_dev *dev,
                              uint32_t index,
                              struct vfio_irq_info *irq,
                              Error **errp)
{
    vfio_user_msg msg = {
        .request = VFIO_USER_REQ_DEV_GET_IRQ_INFO,
        .size = sizeof(msg.payload.u32),
        .payload.u32 = index,
    };

    if (!libvfio_user_write(dev->vfio, &msg, errp)) {
        return false;
    }
    if (!libvfio_user_read(dev->vfio, &msg, errp)) {
        return false;
    }

    return true;
}

static bool
libvfio_user_dev_get_region_info(libvfio_dev *dev, uint32_t index,
                                 struct vfio_region_info *info, Error **errp)
{
    vfio_user_msg msg = {
        .request = VFIO_USER_REQ_DEV_GET_REGION_INFO,
        .size = sizeof(msg.payload.u32),
        .payload.u32 = index,
    };

    if (!libvfio_user_write(dev->vfio, &msg, errp)) {
        return false;
    }
    if (!libvfio_user_read(dev->vfio, &msg, errp)) {
        return false;
    }

    return true;
}

static bool
libvfio_user_dev_get_info(libvfio_dev *dev,
                          struct vfio_device_info *info, Error **errp)
{
    vfio_user_msg msg = {
        .request = VFIO_USER_REQ_DEV_GET_INFO,
    };

    if (!libvfio_user_write(dev->vfio, &msg, errp)) {
        return false;
    }
    if (!libvfio_user_read_hdr(dev->vfio, &msg, errp)) {
        return false;
    }
    if (msg.size != sizeof(*info)) {
        error_setg(errp, "unexpected reply length");
        return false;
    }
    if (!libvfio_user_read_payload(dev->vfio, info, sizeof(*info), errp)) {
        return false;
    }

    return true;
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
    ssize_t ret = 0;

    if (ret < 0) {
        error_setg_errno(errp, -ret, "failed during dev_write");
    }

    return ret;
}

static ssize_t
libvfio_user_dev_read(libvfio_dev *dev,
                      void *buf, size_t size, off_t offset,
                      Error **errp)
{
    ssize_t ret = 0;

    if (ret < 0) {
        error_setg_errno(errp, -ret, "failed during dev_read");
    }

    return ret;
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

static libvfio_ops_t libvfio_user_ops = {
    .init_container = libvfio_user_init_container,
    .container_deinit = libvfio_user_container_deinit,
    .container_check_extension = libvfio_user_container_check_extension,
    .container_set_iommu = libvfio_user_container_set_iommu,
    .container_iommu_get_info = libvfio_user_container_iommu_get_info,
    .container_iommu_map_dma = libvfio_user_container_iommu_map_dma,
    .container_iommu_unmap_dma = libvfio_user_container_iommu_unmap_dma,
    .init_group = libvfio_user_init_group,
    .group_deinit = libvfio_user_group_deinit,
    .group_set_container = libvfio_user_group_set_container,
    .group_unset_container = libvfio_user_group_unset_container,
    .group_get_device = libvfio_user_group_get_device,
    .init_dev = libvfio_user_init_dev,
    .dev_deinit = libvfio_user_dev_deinit,
    .dev_reset = libvfio_user_dev_reset,
    .dev_set_irqs = libvfio_user_dev_set_irqs,
    .dev_get_irq_info = libvfio_user_dev_get_irq_info,
    .dev_get_info = libvfio_user_dev_get_info,
    .dev_get_region_info = libvfio_user_dev_get_region_info,
    /* .dev_get_pci_hot_reset_info = libvfio_user_dev_get_pci_hot_reset_info, */
    /* .dev_pci_hot_reset = libvfio_user_dev_pci_hot_reset, */
    .dev_write = libvfio_user_dev_write,
    .dev_read = libvfio_user_dev_read,
    .dev_mmap = libvfio_user_dev_mmap,
    .dev_unmmap = libvfio_user_dev_unmmap,
};

bool
libvfio_init_user(libvfio_t *vfio,
                  CharBackend *chr,
                  libvfio_get_mem_fd_t *get_mem_fd,
                  Error **errp)
{
    assert(vfio);
    assert(chr);
    assert(get_mem_fd);

    *vfio = (struct libvfio) {
        .chr = chr,
        .get_mem_fd = get_mem_fd,
        .realloc = realloc,
        .ops = &libvfio_user_ops,
    };

    return true;
}

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

typedef struct VuDev {
} VuDev;

typedef struct VuSerialDev {
    VuDev parent;

    /* struct mdev_region_info region_info[VFIO_PCI_NUM_REGIONS]; */
    
} VuSerialDev;

static VuSerialDev serial;
static VuDev *vdev = &serial.parent;

#define MTTY_CONFIG_SPACE_SIZE  0xff
#define MTTY_IO_BAR_SIZE        0x8
#define MTTY_MMIO_BAR_SIZE      0x100000

#define MTTY_VFIO_PCI_OFFSET_SHIFT   40

#define MTTY_VFIO_PCI_OFFSET_TO_INDEX(off)   (off >> MTTY_VFIO_PCI_OFFSET_SHIFT)
#define MTTY_VFIO_PCI_INDEX_TO_OFFSET(index) \
                                ((uint64_t)(index) << MTTY_VFIO_PCI_OFFSET_SHIFT)
#define MTTY_VFIO_PCI_OFFSET_MASK    \
                                (((uint64_t)(1) << MTTY_VFIO_PCI_OFFSET_SHIFT) - 1)

static int
vfio_user_serial_get_device_info(VuDev *dev,
                                 struct vfio_device_info *info)
{
    info->num_regions = VFIO_PCI_NUM_REGIONS;
    info->num_irqs = VFIO_PCI_NUM_IRQS;
    info->flags = VFIO_DEVICE_FLAGS_PCI;

    return 0;
}

static int
vfio_user_serial_get_region_info(VuDev *dev,
                                 struct vfio_region_info *info)
{
    /* VuSerialDev *serial = container_of(dev, VuSerialDev, parent); */

    switch (info->index) {
    case VFIO_PCI_CONFIG_REGION_INDEX:
        info->size = MTTY_CONFIG_SPACE_SIZE;
        break;
    case VFIO_PCI_BAR0_REGION_INDEX:
        info->size = MTTY_IO_BAR_SIZE;
        break;
    default:
        info->size = 0;
        break;
    }

    info->offset = MTTY_VFIO_PCI_INDEX_TO_OFFSET(info->index);
    info->flags = VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE;
    return 0;
}

static int
vfio_user_serial_get_irq_info(VuDev *dev, struct vfio_irq_info *info)
{
    switch (info->index) {
    case VFIO_PCI_INTX_IRQ_INDEX:
    case VFIO_PCI_MSI_IRQ_INDEX:
    case VFIO_PCI_REQ_IRQ_INDEX:
        break;

    default:
        return -EINVAL;
    }

    info->flags = VFIO_IRQ_INFO_EVENTFD;
    info->count = 1;

    if (info->index == VFIO_PCI_INTX_IRQ_INDEX) {
        info->flags |= (VFIO_IRQ_INFO_MASKABLE | VFIO_IRQ_INFO_AUTOMASKED);
    } else {
        info->flags |= VFIO_IRQ_INFO_NORESIZE;
    }

    return 0;
}

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
    if (ext == VFIO_TYPE1_IOMMU || VFIO_TYPE1v2_IOMMU) {
        return true;
    }

    return false;
}

static bool
libvfio_user_container_set_iommu(libvfio_container *container, int iommu_type,
                                 Error **errp)
{
    return true;
}

static bool
libvfio_user_container_iommu_get_info(libvfio_container *container,
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
libvfio_user_container_iommu_map_dma(libvfio_container *container,
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
libvfio_user_container_iommu_unmap_dma(libvfio_container *container,
                                       uint64_t iova, uint64_t size,
                                       uint32_t flags, Error **errp)
{
    g_debug("unmap_dma iova:0x%" PRIx64 " size:0x%" PRIx64 " flags:0x%" PRIx32,
            iova, size, flags);

    return true;
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
    /* XXX: could learn to lookup a specific device */
    return true;
}

static bool
libvfio_user_group_set_container(libvfio_group *group,
                                 libvfio_container *container,
                                 Error **errp)
{
    return true;
}

static bool
libvfio_user_group_unset_container(libvfio_group *group,
                                   libvfio_container *container,
                                   Error **errp)
{
    return true;
}

static bool
libvfio_user_init_dev(libvfio *vfio, libvfio_dev *dev,
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
    vfio_user_serial_get_irq_info(vdev, index, irq);
    return false;
}

static bool
libvfio_user_write(libvfio *vfio, vfio_user_msg *msg, Error **errp)
{
    int size = VFIO_USER_HDR_SIZE + msg->size;
    int ret = qemu_chr_fe_write_all(vfio->chr, (uint8_t*)msg, size);

    if (ret != size) {
        error_setg(errp, "failed to write %d bytes, wrote %d", size, ret);
        return false;
    }

    return true;
}

static bool
libvfio_user_read_hdr(libvfio *vfio, vfio_user_msg *msg, Error **errp)
{
    int size = VFIO_USER_HDR_SIZE;
    int ret = qemu_chr_fe_read_all(vfio->chr, (uint8_t*)msg, size);

    if (ret != size) {
        error_setg(errp, "failed to read %d bytes, read %d", size, ret);
        return false;
    }

    return true;
}

static bool
libvfio_user_read_payload(libvfio *vfio, void *payload,
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
libvfio_user_dev_get_info(libvfio_dev *dev,
                          struct vfio_device_info *info, Error **errp)
{
#if 0
    vfio_user_msg msg = {
        .req = VFIO_USER_REQ_DEV_GET_INFO,
        .size = sizeof(msg.u64),
        .u64 = sizeof(*info),
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
#endif
    vfio_user_serial_get_device_info(vdev, info);

    return true;
}

static bool
libvfio_user_dev_get_region_info(libvfio_dev *dev, int index,
                                 struct vfio_region_info *info, Error **errp)
{
    vfio_user_serial_get_region_info(vdev, info);

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
    /* .dev_reset = libvfio_user_dev_reset, */
    /* .dev_set_irqs = libvfio_user_dev_set_irqs, */
    .dev_get_irq_info = libvfio_user_dev_get_irq_info,
    .dev_get_info = libvfio_user_dev_get_info,
    .dev_get_region_info = libvfio_user_dev_get_region_info,
    /* .dev_get_pci_hot_reset_info = libvfio_user_dev_get_pci_hot_reset_info, */
    /* .dev_pci_hot_reset = libvfio_user_dev_pci_hot_reset, */
    /* .dev_write = libvfio_user_dev_write, */
    .dev_read = libvfio_user_dev_read,
    /* .dev_mmap = libvfio_user_dev_mmap, */
    /* .dev_unmmap = libvfio_user_dev_unmmap, */
};

bool
libvfio_init_user(libvfio *vfio,
                  CharBackend *chr,
                  libvfio_get_mem_fd *get_mem_fd,
                  Error **errp)
{
    assert(vfio);
    assert(chr);
    assert(get_mem_fd);

    *vfio = (struct libvfio) {
        .chr = chr,
        .get_mem_fd = get_mem_fd,
        .ops = &libvfio_user_ops,
    };

    return true;
}

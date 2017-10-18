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

#define LIBVFIO_CALL(vfio, miss, op, ...) ({                        \
    typeof(miss) _ret = (miss);                                     \
    assert(vfio);                                                   \
    assert(vfio->ops);                                              \
    if (!vfio->ops->op) {                                           \
        error_setg(errp, ERR_PREFIX "'%s' op not implemented",  \
                   G_STRINGIFY(op));                                \
    } else {                                                        \
        _ret = (vfio)->ops->op(__VA_ARGS__);                        \
    }                                                               \
    _ret;                                                           \
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
libvfio_init_dev(libvfio *vfio, libvfio_dev *dev,
                 const char *path, Error **errp)
{
    char *tmp, group_path[PATH_MAX], *group_name;
    struct stat st;
    ssize_t len;
    int groupid;

    if (stat(path, &st) < 0) {
        error_setg_errno(errp, errno, ERR_PREFIX "no such host device");
        return false;
    }

    tmp = g_strdup_printf("%s/iommu_group", path);
    len = readlink(tmp, group_path, sizeof(group_path));
    g_free(tmp);

    if (len <= 0 || len >= sizeof(group_path)) {
        error_setg_errno(errp, len < 0 ? errno : ENAMETOOLONG,
                         "no iommu_group found");
        return false;
    }

    group_path[len] = 0;

    group_name = basename(group_path);
    if (sscanf(group_name, "%d", &groupid) != 1) {
        error_setg_errno(errp, errno, "failed to read %s", group_path);
        return false;
    }

    dev->vfio = vfio;
    dev->groupid = groupid;
    dev->name = g_strdup(basename(path));
    return true;
}

void
libvfio_dev_deinit(libvfio_dev *dev)
{
    if (!dev->vfio) {
        return;
    }

    if (dev->fd >= 0) {
        qemu_close(dev->fd);
        dev->fd = -1;
    }
    g_free(dev->name);
    dev->name = NULL;
}

bool
libvfio_init_group(libvfio *vfio, libvfio_group *group,
                   int groupid, Error **errp)
{
    char path[32];
    struct vfio_group_status status = { .argsz = sizeof(status) };

    snprintf(path, sizeof(path), "/dev/vfio/%d", groupid);
    group->fd = qemu_open(path, O_RDWR);
    if (group->fd < 0) {
        error_setg_errno(errp, errno, "failed to open %s", path);
        return false;
    }

    if (ioctl(group->fd, VFIO_GROUP_GET_STATUS, &status)) {
        error_setg_errno(errp, errno, "failed to get group %d status", groupid);
        goto close_fd_exit;
    }

    if (!(status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
        error_setg(errp, "group %d is not viable", groupid);
        error_append_hint(errp,
                          "Please ensure all devices within the iommu_group "
                          "are bound to their vfio bus driver.\n");
        goto close_fd_exit;
    }

    group->vfio = vfio;
    group->groupid = groupid;
    return true;

close_fd_exit:
    qemu_close(group->fd);
    return false;
}

void
libvfio_group_deinit(libvfio_group *group)
{
    if (!group->vfio) {
        return;
    }

    if (group->fd >= 0) {
        qemu_close(group->fd);
        group->fd = -1;
    }

    group->vfio = NULL;
}

bool
libvfio_group_get_device(libvfio_group *group, libvfio_dev *dev, Error **errp)
{
    int fd = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD, dev->name);

    if (fd < 0) {
        error_setg_errno(errp, errno, "error getting device from group %d",
                         group->groupid);
        error_append_hint(errp,
                          "Verify all devices in group %d are bound to vfio-<bus> "
                          "or pci-stub and not already in use\n",
                          group->groupid);
        return false;
    }

    dev->fd = fd;
    return true;
}

bool
libvfio_group_set_container(libvfio_group *group, libvfio_container *container,
                            Error **errp)
{
    if (ioctl(group->fd, VFIO_GROUP_SET_CONTAINER, &container->fd)) {
        error_setg_errno(errp, errno, "failed to set group container");
        return false;
    }

    return true;
}

bool
libvfio_group_unset_container(libvfio_group *group, libvfio_container *container,
                              Error **errp)
{
    if (ioctl(group->fd, VFIO_GROUP_UNSET_CONTAINER, &container->fd)) {
        error_setg_errno(errp, errno, "failed to unset group container");
        return false;
    }

    return true;
}

const char *
libvfio_dev_get_name(libvfio_dev *dev)
{
    return dev->name;
}

int
libvfio_dev_get_groupid(libvfio_dev *dev)
{
    return dev->groupid;
}

bool
libvfio_dev_reset(libvfio_dev *dev, Error **errp)
{
    if (ioctl(dev->fd, VFIO_DEVICE_RESET)) {
        error_setg_errno(errp, errno, "vfio: Failed to reset device");
        return false;
    }

    return true;
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
    struct vfio_irq_set *irq_set;
    int argsz, i;
    int32_t *pfd;

    argsz = sizeof(*irq_set) + sizeof(*pfd) * nfds;
    irq_set = g_alloca(argsz);
    *irq_set = (struct vfio_irq_set) {
        .argsz = argsz,
        .flags = flags,
        .index = index,
        .start = start,
        .start = 0,
        .count = nfds,
    };
    pfd = (int32_t *)&irq_set->data;
    for (i = 0; i < nfds; i++) {
        pfd[i] = fds[i];
    }

    if (ioctl(dev->fd, VFIO_DEVICE_SET_IRQS, irq_set)) {
        error_setg_errno(errp, errno, "vfio: Failed to set trigger eventfd");
        return false;
    }

    return true;
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
    irq->argsz = sizeof(*irq);
    irq->index = index;
    if (ioctl(dev->fd, VFIO_DEVICE_GET_IRQ_INFO, irq)) {
        error_setg_errno(errp, errno, "failed to get device irq info");
        return false;
    }

    return true;
}

bool
libvfio_dev_get_info(libvfio_dev *dev,
                     struct vfio_device_info *info, Error **errp)
{
    info->argsz = sizeof(*info);

    if (ioctl(dev->fd, VFIO_DEVICE_GET_INFO, info)) {
        error_setg_errno(errp, errno, "error getting device info");
        return false;
    }

    return true;
}

bool
libvfio_dev_get_region_info(libvfio_dev *dev, int index,
                            struct vfio_region_info *info, Error **errp)
{
    assert(info->argsz >= sizeof(*info));

    int ret = ioctl(dev->fd, VFIO_DEVICE_GET_REGION_INFO, info);
    if (ret && errno != ENOSPC) {
        error_setg_errno(errp, errno, "error getting region info");
        return false;
    }

    return true;
}

bool
libvfio_dev_get_pci_hot_reset_info(libvfio_dev *dev,
                                   struct vfio_pci_hot_reset_info *info,
                                   Error **errp)
{
    assert(info->argsz >= sizeof(*info));

    int ret = ioctl(dev->fd, VFIO_DEVICE_GET_PCI_HOT_RESET_INFO, info);
    if (ret && errno != ENOSPC) {
        error_setg_errno(errp, errno, "error getting PCI hot reset info");
        return false;
    }

    return true;
}

bool
libvfio_dev_pci_hot_reset(libvfio_dev *dev,
                          int *fds, int nfds,
                          Error **errp)
{
    int argsz, i;
    struct vfio_pci_hot_reset *reset;
    int32_t *pfd;

    argsz = sizeof(*reset) + sizeof(*pfd) * nfds;
    reset = g_alloca(argsz);
    *reset = (struct vfio_pci_hot_reset) {
        .argsz = argsz,
    };
    pfd = &reset->group_fds[0];
    for (i = 0; i < nfds; i++) {
        pfd[i] = fds[i];
    }

    if (ioctl(dev->fd, VFIO_DEVICE_PCI_HOT_RESET, reset)) {
        error_setg_errno(errp, errno, "error hot reseting PCI");
        return false;
    }

    return true;
}

ssize_t
libvfio_dev_write(libvfio_dev *dev,
                  const void *buf, size_t size, off_t offset,
                  Error **errp)
{
    ssize_t ret;

again:
    ret = pwrite(dev->fd, buf, size, offset);
    if (ret < 0) {
        if (errno == EINTR) {
            goto again;
        }
        error_setg_errno(errp, errno, "pwrite() failed");
        return -1;
    }

    return ret;
}

ssize_t
libvfio_dev_read(libvfio_dev *dev,
                 void *buf, size_t size, off_t offset,
                 Error **errp)
{
    ssize_t ret;

again:
    ret = pread(dev->fd, buf, size, offset);
    if (ret < 0) {
        if (errno == EINTR) {
            goto again;
        }
        error_setg_errno(errp, errno, "pread() failed");
        return -1;
    }

    return ret;
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
    void *ret = mmap(NULL, length, prot, flags, dev->fd, offset);
    if (ret == MAP_FAILED) {
        error_setg_errno(errp, errno, "mmap() failed");
    }

    return ret;
}

bool
libvfio_dev_unmmap(libvfio_dev *dev, void *addr, size_t length, Error **errp)
{
    if (munmap(addr, length) < 0) {
        error_setg_errno(errp, errno, "munmap() failed");
        return false;
    }

    return true;
}

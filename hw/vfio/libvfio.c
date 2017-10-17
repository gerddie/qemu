#include "hw/vfio/libvfio.h"
#include "qapi/error.h"
#include <sys/ioctl.h>

#define ERR_PREFIX "libvfio error: %s: "

bool
libvfio_init_host(libvfio *vfio, Error **errp)
{
    vfio->fd = -1;
    return true;
}

bool
libvfio_init_user(libvfio *vfio, int fd, Error **errp)
{
    vfio->fd = fd;
    return true;
}

bool
libvfio_init_container(libvfio *vfio, libvfio_container *container,
                       Error **errp)
{
    int ret, fd = qemu_open("/dev/vfio/vfio", O_RDWR);

    if (fd < 0) {
        error_setg_errno(errp, errno, "failed to open /dev/vfio/vfio");
        return false;
    }

    ret = ioctl(fd, VFIO_GET_API_VERSION);
    if (ret != VFIO_API_VERSION) {
        error_setg(errp, "supported vfio version: %d, "
                   "reported version: %d", VFIO_API_VERSION, ret);
        close(fd);
        return false;
    }

    container->vfio = vfio;
    container->fd = fd;
    return true;
}

void
libvfio_container_deinit(libvfio_container *container)
{
    if (!container->vfio) {
        return;
    }

    close(container->fd);
    container->vfio = NULL;
}

bool
libvfio_container_check_extension(libvfio_container *container,
                                  int ext)
{
    return ioctl(container->fd, VFIO_CHECK_EXTENSION, ext) > 0;
}

bool
libvfio_container_set_iommu(libvfio_container *container, int iommu_type,
                            Error **errp)
{
    if (ioctl(container->fd, VFIO_SET_IOMMU, iommu_type)) {
        error_setg_errno(errp, errno, "failed to set iommu for container");
        return false;
    }

    return true;
}

bool
libvfio_container_iommu_get_info(libvfio_container *container,
                                 struct vfio_iommu_type1_info *info,
                                 Error **errp)
{
    info->argsz = sizeof(*info);
    if (ioctl(container->fd, VFIO_IOMMU_GET_INFO, info)) {
        error_setg_errno(errp, errno, "failed to get iommu info");
        return false;
    }

    return true;
}

bool
libvfio_container_iommu_enable(libvfio_container *container, Error **errp)
{
    if (ioctl(container->fd, VFIO_IOMMU_ENABLE)) {
        error_setg_errno(errp, errno, "failed to enable container");
        return false;
    }

    return true;
}

bool
libvfio_container_iommu_map_dma(libvfio_container *container,
                                uint64_t vaddr, uint64_t iova,
                                uint64_t size, uint32_t flags,
                                Error **errp)
{
    struct vfio_iommu_type1_dma_map map = {
        .argsz = sizeof(map),
        .flags = flags,
        .vaddr = vaddr,
        .iova = iova,
        .size = size,
    };

    /*
     * Try the mapping, if it fails with EBUSY, unmap the region and try
     * again.  This shouldn't be necessary, but we sometimes see it in
     * the VGA ROM space.
     */
    if (ioctl(container->fd, VFIO_IOMMU_MAP_DMA, &map) == 0) {
        return true;
    }

    if (errno != EBUSY) {
        goto error;
    }

    if (!libvfio_container_iommu_unmap_dma(container, iova, size, 0, NULL)) {
        goto error;
    }

    if (ioctl(container->fd, VFIO_IOMMU_MAP_DMA, &map) == 0) {
        return true;
    }

error:
    error_setg_errno(errp, errno, "VFIO_MAP_DMA failed");
    return false;
}

bool
libvfio_container_iommu_unmap_dma(libvfio_container *container,
                                  uint64_t iova, uint64_t size,
                                  uint32_t flags, Error **errp)
{
    struct vfio_iommu_type1_dma_unmap unmap = {
        .argsz = sizeof(unmap),
        .flags = 0,
        .iova = iova,
        .size = size,
    };

    if (ioctl(container->fd, VFIO_IOMMU_UNMAP_DMA, &unmap)) {
        error_setg_errno(errp, errno, "VFIO_UNMAP_DMA failed");
        return false;
    }

    return true;
}

bool
libvfio_container_iommu_spapr_tce_get_info(libvfio_container *container,
                                         struct vfio_iommu_spapr_tce_info *info,
                                         Error **errp)
{
    info->argsz = sizeof(*info);
    if (ioctl(container->fd, VFIO_IOMMU_SPAPR_TCE_GET_INFO, info)) {
        error_setg_errno(errp, errno,
                         "VFIO_IOMMU_SPAPR_TCE_GET_INFO failed");
        return false;
    }

    return true;
}

bool
libvfio_container_iommu_spapr_register_memory(libvfio_container *container,
                                              uint64_t vaddr,
                                              uint64_t size,
                                              uint32_t flags,
                                              Error **errp)
{
    struct vfio_iommu_spapr_register_memory reg = {
        .argsz = sizeof(reg),
        .vaddr = vaddr,
        .size = size,
        .flags = flags,
    };

    if (ioctl(container->fd, VFIO_IOMMU_SPAPR_REGISTER_MEMORY, &reg)) {
        error_setg_errno(errp, errno,
                         "VFIO_IOMMU_SPAPR_REGISTER_MEMORY failed");
        return false;
    }

    return true;
}

bool
libvfio_container_iommu_spapr_unregister_memory(libvfio_container *container,
                                                uint64_t vaddr,
                                                uint64_t size,
                                                uint32_t flags,
                                                Error **errp)
{
    struct vfio_iommu_spapr_register_memory reg = {
        .argsz = sizeof(reg),
        .vaddr = vaddr,
        .size = size,
        .flags = flags,
    };

    if (ioctl(container->fd, VFIO_IOMMU_SPAPR_UNREGISTER_MEMORY, &reg)) {
        error_setg_errno(errp, errno,
                         "VFIO_IOMMU_SPAPR_UNREGISTER_MEMORY failed");
        return false;
    }

    return true;
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
    struct vfio_iommu_spapr_tce_create create = {
        .argsz = sizeof(create),
        .page_shift = page_shift,
        .window_size = window_size,
        .levels = levels,
        .flags = flags
    };

    if (!ioctl(container->fd, VFIO_IOMMU_SPAPR_TCE_CREATE, &create)) {
        error_setg_errno(errp, errno,
                         "VFIO_IOMMU_SPAPR_TCE_CREATE failed");
        return false;
    }

    *start_addr = create.start_addr;
    return true;
}

bool
libvfio_container_iommu_spapr_tce_remove(libvfio_container *container,
                                         uint64_t start_addr,
                                         Error **errp)
{
    struct vfio_iommu_spapr_tce_remove remove = {
        .argsz = sizeof(remove),
        .start_addr = start_addr,
    };

    if (ioctl(container->fd, VFIO_IOMMU_SPAPR_TCE_REMOVE, &remove)) {
        error_setg(errp, "Failed to remove window at %"PRIx64,
                   (uint64_t)remove.start_addr);
        return false;
    }

    return true;
}

bool
libvfio_container_eeh_pe_op(libvfio_container *container,
                            uint32_t op, Error **errp)
{
    struct vfio_eeh_pe_op pe_op = {
        .argsz = sizeof(pe_op),
        .op = op,
    };

    if (ioctl(container->fd, VFIO_EEH_PE_OP, &pe_op)) {
        error_setg_errno(errp, errno, "vfio/eeh: EEH_PE_OP 0x%x failed", op);
        return false;
    }

    return true;
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
        error_setg_errno(errp, errno, "no such host device");
        error_prepend(errp, ERR_PREFIX, path);
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
    close(group->fd);
    return false;
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

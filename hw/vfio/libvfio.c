#include "hw/vfio/libvfio.h"
#include "qapi/error.h"

#define ERR_PREFIX "libvfio error: %s: "

bool
libvfio_init_host(libvfio *vfio, Error **errp)
{
    return true;
}

bool
libvfio_init_user(libvfio *vfio, int fd, Error **errp)
{
    vfio->fd = fd;
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

    dev->group = groupid;
    dev->name = g_strdup(basename(path));
    return true;
}

const char *
libvfio_dev_get_name(libvfio_dev *dev)
{
    return dev->name;
}

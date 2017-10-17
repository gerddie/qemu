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

static bool
libvfio_host_init_container(libvfio *vfio, libvfio_container *container,
                            Error **errp)
{
    int ret, fd = qemu_open("/dev/vfio/vfio", O_RDWR);

    if (fd < 0) {
        error_setg_errno(errp, errno,
                         ERR_PREFIX "failed to open /dev/vfio/vfio");
        return false;
    }

    ret = ioctl(fd, VFIO_GET_API_VERSION);
    if (ret != VFIO_API_VERSION) {
        error_setg(errp, ERR_PREFIX "supported vfio version: %d, "
                   "reported version: %d", VFIO_API_VERSION, ret);
        qemu_close(fd);
        return false;
    }

    container->vfio = vfio;
    container->fd = fd;
    return true;
}

static void
libvfio_host_container_deinit(libvfio_container *container)
{
    if (container->fd >= 0) {
        qemu_close(container->fd);
        container->fd = -1;
    }
}

static bool
libvfio_host_container_check_extension(libvfio_container *container,
                                       int ext, Error **errp)
{
    int ret = ioctl(container->fd, VFIO_CHECK_EXTENSION, ext);

    if (ret < 0) {
        error_setg_errno(errp, errno,
                         ERR_PREFIX "ioctl(CHECK_EXTENSION) failed");
        return false;
    } else if (ret > 0) {
        return true;
    }
    return false;
}

static libvfio_ops libvfio_host_ops = {
    .init_container = libvfio_host_init_container,
    .container_deinit = libvfio_host_container_deinit,
    .container_check_extension = libvfio_host_container_check_extension,
};

bool
libvfio_init_host(libvfio *vfio, int api_version, Error **errp)
{
    assert(vfio);

    if (VFIO_API_VERSION != api_version) {
        error_setg(errp, ERR_PREFIX "supported vfio version: %d, "
                   "client version: %d", VFIO_API_VERSION, api_version);
        return false;
    }

    vfio->fd = -1;
    vfio->ops = &libvfio_host_ops;
    return true;
}

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
    return false;
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

static libvfio_ops libvfio_user_ops = {
    .init_container = libvfio_user_init_container,
    .container_deinit = libvfio_user_container_deinit,
    .container_check_extension = libvfio_user_container_check_extension,
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

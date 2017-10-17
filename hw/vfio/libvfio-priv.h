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
};

G_END_DECLS

#endif /* LIBVFIO_PRIV_H_ */

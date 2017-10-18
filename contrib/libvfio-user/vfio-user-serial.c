/*
 * vfio-user-serial sample
 *
 * Copyright (c) 2017 Red Hat, Inc.
 *
 * Authors:
 *  Marc-André Lureau <mlureau@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

#include "libvfio-user-glib.h"

static void
vfio_user_serial_panic(VuDev *dev, const char *err)
{
    g_error("%s\n", err);
}

static VuDevIface vfio_user_serial_iface = {
};

int
main(int argc, char *argv[])
{
    int sock;
    VugDev dev;

    vug_init(&dev, sock, vfio_user_serial_panic, &vfio_user_serial_iface);

    vug_deinit(&dev);

    return 0;
}

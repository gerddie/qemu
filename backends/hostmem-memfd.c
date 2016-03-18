/*
 * QEMU host memfd memory backend
 *
 * Copyright (C) 2016 Red Hat Inc
 *
 * Authors:
 *   Marc-André Lureau <marcandre.lureau@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "sysemu/hostmem.h"
#include "sysemu/sysemu.h"
#include "qom/object_interfaces.h"
#include "qemu/memfd.h"
#include "qapi/error.h"

/* hostmem-memfd.c */
/**
 * @TYPE_MEMORY_BACKEND_MEMFD:
 * name of backend that uses mmap on a file descriptor
 */
#define TYPE_MEMORY_BACKEND_MEMFD "memory-backend-memfd"

#define MEMORY_BACKEND_MEMFD(obj) \
    OBJECT_CHECK(HostMemoryBackendMemfd, (obj), TYPE_MEMORY_BACKEND_MEMFD)

typedef struct HostMemoryBackendMemfd HostMemoryBackendMemfd;

struct HostMemoryBackendMemfd {
    HostMemoryBackend parent_obj;

    int fd;
};

static void
memfd_backend_memory_alloc(HostMemoryBackend *backend, Error **errp)
{
    void *ptr;
    int fd;

    if (!backend->size) {
        error_setg(errp, "can't create backend with size 0");
        return;
    }
#ifndef CONFIG_LINUX
    error_setg(errp, "memfd not supported on this host");
#else
    if (!memory_region_size(&backend->mr)) {
        backend->force_prealloc = mem_prealloc;
        ptr = qemu_memfd_alloc(TYPE_MEMORY_BACKEND_MEMFD,
                               backend->size,
                               F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL,
                               &fd);
        if (!ptr) {
            error_setg(errp, "can't allocate memfd backend");
            return;
        }
        memory_region_init_ram_ptr(&backend->mr, OBJECT(backend),
                                   object_get_canonical_path(OBJECT(backend)),
                                   backend->size, ptr, fd);
    }
#endif
}

static void
memfd_backend_class_init(ObjectClass *oc, void *data)
{
    HostMemoryBackendClass *bc = MEMORY_BACKEND_CLASS(oc);

    bc->alloc = memfd_backend_memory_alloc;
}

static const TypeInfo memfd_backend_info = {
    .name = TYPE_MEMORY_BACKEND_MEMFD,
    .parent = TYPE_MEMORY_BACKEND,
    .class_init = memfd_backend_class_init,
    .instance_size = sizeof(HostMemoryBackendMemfd),
};

static void register_types(void)
{
    type_register_static(&memfd_backend_info);
}

type_init(register_types);

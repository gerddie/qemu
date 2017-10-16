#include "qemu/osdep.h"

typedef struct libvfio {
    bool host;
    int fd;
} libvfio;

typedef struct libvfio_dev {
    int group;
    char *name;
} libvfio_dev;

bool libvfio_init_host(libvfio *vfio, Error **errp);
bool libvfio_init_user(libvfio *vfio, int fd, Error **errp);

bool libvfio_init_dev(libvfio *vfio, libvfio_dev *dev,
                      const char *path, Error **errp);

const char *libvfio_dev_get_name(libvfio_dev *dev);

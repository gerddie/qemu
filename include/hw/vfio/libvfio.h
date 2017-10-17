#ifndef LIBVFIO_H_
#define LIBVFIO_H_

#include "qemu/osdep.h"
#include <linux/vfio.h>

typedef struct libvfio {
    int fd; /* user-fd */
} libvfio;

typedef struct libvfio_container {
    libvfio *vfio;
    int fd;
} libvfio_container;

typedef struct libvfio_group {
    libvfio *vfio;
    int fd;
    int groupid;
} libvfio_group;

typedef struct libvfio_dev {
    libvfio *vfio;
    int fd;
    int groupid;
    char *name;
} libvfio_dev;

bool libvfio_init_host(libvfio *vfio, Error **errp);
bool libvfio_init_user(libvfio *vfio, int fd, Error **errp);

bool libvfio_init_container(libvfio *vfio, libvfio_container *container,
                            Error **errp);
void libvfio_container_deinit(libvfio_container *container);
bool libvfio_container_check_extension(libvfio_container *container,
                                       int ext);
bool libvfio_container_set_iommu(libvfio_container *container, int iommu_type,
                                 Error **errp);
bool libvfio_container_iommu_get_info(libvfio_container *container,
                                      struct vfio_iommu_type1_info *info,
                                      Error **errp);
bool libvfio_container_iommu_enable(libvfio_container *container, Error **errp);
bool libvfio_container_iommu_map_dma(libvfio_container *container,
                                     uint64_t vaddr, uint64_t iova,
                                     uint64_t size, uint32_t flags,
                                     Error **errp);
bool libvfio_container_iommu_unmap_dma(libvfio_container *container,
                                       uint64_t iova, uint64_t size,
                                       uint32_t flags, Error **errp);
bool libvfio_container_iommu_spapr_tce_get_info(libvfio_container *container,
                                         struct vfio_iommu_spapr_tce_info *info,
                                         Error **errp);
bool libvfio_container_iommu_spapr_register_memory(libvfio_container *container,
                                                   uint64_t vaddr,
                                                   uint64_t size,
                                                   uint32_t flags,
                                                   Error **errp);
bool libvfio_container_iommu_spapr_unregister_memory(libvfio_container *container,
                                                     uint64_t vaddr,
                                                     uint64_t size,
                                                     uint32_t flags,
                                                     Error **errp);
bool libvfio_container_iommu_spapr_tce_create(libvfio_container *container,
                                              uint32_t page_shift,
                                              uint64_t window_size,
                                              uint32_t levels,
                                              uint32_t flags,
                                              uint64_t *start_addr,
                                              Error **errp);
bool libvfio_container_iommu_spapr_tce_remove(libvfio_container *container,
                                              uint64_t start_addr,
                                              Error **errp);
bool libvfio_container_eeh_pe_op(libvfio_container *container,
                                 uint32_t op, Error **errp);

bool libvfio_init_group(libvfio *vfio, libvfio_group *group,
                        int groupid, Error **errp);
bool libvfio_group_set_container(libvfio_group *group,
                                 libvfio_container *container,
                                 Error **errp);
bool libvfio_group_unset_container(libvfio_group *group,
                                   libvfio_container *container,
                                   Error **errp);
bool libvfio_group_get_device(libvfio_group *group,
                              libvfio_dev *dev,
                              Error **errp);

bool libvfio_init_dev(libvfio *vfio, libvfio_dev *dev,
                      const char *path, Error **errp);
const char *libvfio_dev_get_name(libvfio_dev *dev);
int libvfio_dev_get_groupid(libvfio_dev *dev);
bool libvfio_dev_reset(libvfio_dev *dev, Error **errp);
bool libvfio_dev_set_irq(libvfio_dev *dev,
                         uint32_t index,
                         uint32_t flags,
                         Error **errp);
bool libvfio_dev_set_irq_fd(libvfio_dev *dev,
                            uint32_t index,
                            int fd,
                            uint32_t flags,
                            Error **errp);
bool libvfio_dev_set_irqs(libvfio_dev *dev,
                          uint32_t index,
                          uint32_t start,
                          int *fds,
                          size_t nfd,
                          uint32_t flags,
                          Error **errp);
bool libvfio_dev_get_irq_info(libvfio_dev *dev,
                              uint32_t index,
                              struct vfio_irq_info *irq,
                              Error **errp);
bool libvfio_dev_get_info(libvfio_dev *dev,
                          struct vfio_device_info *info,
                          Error **errp);
bool libvfio_dev_get_region_info(libvfio_dev *dev, int index,
                                 struct vfio_region_info *info, Error **errp);

#endif /* LIBVFIO_H_ */

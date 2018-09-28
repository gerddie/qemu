#ifndef HW_VFIO_H
#define HW_VFIO_H

#include "hw/vfio/vfio-common.h"

bool vfio_eeh_as_ok(AddressSpace *as);
int vfio_eeh_as_op(AddressSpace *as, uint32_t op);

#endif

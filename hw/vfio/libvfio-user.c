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
#include "vfio-user.h"

#include <linux/pci.h>

typedef struct VuDev {
} VuDev;

#define MTTY_CONFIG_SPACE_SIZE  0xff
#define MTTY_IO_BAR_SIZE        0x8
#define MTTY_MMIO_BAR_SIZE      0x100000

#define STORE_LE16(addr, val)   (*(uint16_t *)addr = val)
#define STORE_LE32(addr, val)   (*(uint32_t *)addr = val)

#define MAX_FIFO_SIZE   16

#define CIRCULAR_BUF_INC_IDX(idx)    (idx = (idx + 1) & (MAX_FIFO_SIZE - 1))

#define MTTY_VFIO_PCI_OFFSET_SHIFT   40

#define MTTY_VFIO_PCI_OFFSET_TO_INDEX(off)   (off >> MTTY_VFIO_PCI_OFFSET_SHIFT)
#define MTTY_VFIO_PCI_INDEX_TO_OFFSET(index)            \
    ((uint64_t)(index) << MTTY_VFIO_PCI_OFFSET_SHIFT)
#define MTTY_VFIO_PCI_OFFSET_MASK                       \
    (((uint64_t)(1) << MTTY_VFIO_PCI_OFFSET_SHIFT) - 1)

struct region_info {
    uint64_t start;
    uint64_t phys_start;
    uint32_t size;
    uint64_t vfio_offset;
};

const char *wr_reg[] = {
    "TX",
    "IER",
    "FCR",
    "LCR",
    "MCR",
    "LSR",
    "MSR",
    "SCR"
};

const char *rd_reg[] = {
    "RX",
    "IER",
    "IIR",
    "LCR",
    "MCR",
    "LSR",
    "MSR",
    "SCR"
};

/* loop back buffer */
struct rxtx {
        uint8_t fifo[MAX_FIFO_SIZE];
        uint8_t head, tail;
        uint8_t count;
};

struct serial_port {
        uint8_t uart_reg[8];         /* 8 registers */
        struct rxtx rxtx;       /* loop back buffer */
        bool dlab;
        bool overrun;
        uint16_t divisor;
        uint8_t fcr;                 /* FIFO control register */
        uint8_t max_fifo_size;
        uint8_t intr_trigger_level;  /* interrupt trigger level */
};

typedef struct VuSerialDev {
    VuDev parent;

    struct region_info region_info[VFIO_PCI_NUM_REGIONS];
    uint32_t bar_mask[VFIO_PCI_NUM_REGIONS];
    struct vfio_device_info dev_info;
    int irq_index;
    char vconfig[MTTY_CONFIG_SPACE_SIZE];
    struct serial_port s;
} VuSerialDev;

static VuSerialDev serial;
static VuDev *vdev = &serial.parent;

static void
vfio_user_serial_read_base(VuDev *dev)
{
    VuSerialDev *serial = container_of(dev, VuSerialDev, parent);
    int index, pos;
    uint32_t start_lo, start_hi;
    uint32_t mem_type;

    pos = PCI_BASE_ADDRESS_0;

    for (index = 0; index <= VFIO_PCI_BAR5_REGION_INDEX; index++) {

        if (!serial->region_info[index].size)
            continue;

        start_lo = (*(uint32_t *)(serial->vconfig + pos)) &
            PCI_BASE_ADDRESS_MEM_MASK;
        mem_type = (*(uint32_t *)(serial->vconfig + pos)) &
            PCI_BASE_ADDRESS_MEM_TYPE_MASK;

        switch (mem_type) {
        case PCI_BASE_ADDRESS_MEM_TYPE_64:
            start_hi = (*(uint32_t *)(serial->vconfig + pos + 4));
            pos += 4;
            break;
        case PCI_BASE_ADDRESS_MEM_TYPE_32:
        case PCI_BASE_ADDRESS_MEM_TYPE_1M:
            /* 1M mem BAR treated as 32-bit BAR */
        default:
            /* mem unknown type treated as 32-bit BAR */
            start_hi = 0;
            break;
        }
        pos += 4;
        serial->region_info[index].start =
            ((uint64_t)start_hi << 32) | start_lo;
    }
}

static void handle_pci_cfg_write(VuSerialDev *serial, uint16_t offset,
                                 char *buf, uint32_t count)
{
    uint32_t cfg_addr, bar_mask, bar_index = 0;

    switch (offset) {
    case 0x04: /* device control */
    case 0x06: /* device status */
        /* do nothing */
        break;
    case 0x3c:  /* interrupt line */
        serial->vconfig[0x3c] = buf[0];
        break;
    case 0x3d:
        /*
         * Interrupt Pin is hardwired to INTA.
         * This field is write protected by hardware
         */
        break;
    case 0x10:  /* BAR0 */
    case 0x14:  /* BAR1 */
        if (offset == 0x10)
            bar_index = 0;
        else if (offset == 0x14)
            bar_index = 1;

        if (bar_index == 1) {
            STORE_LE32(&serial->vconfig[offset], 0);
            break;
        }

        cfg_addr = *(uint32_t *)buf;
        g_debug("BAR%d addr 0x%x", bar_index, cfg_addr);

        if (cfg_addr == 0xffffffff) {
            bar_mask = serial->bar_mask[bar_index];
            cfg_addr = (cfg_addr & bar_mask);
        }

        cfg_addr |= (serial->vconfig[offset] & 0x3ul);
        STORE_LE32(&serial->vconfig[offset], cfg_addr);
        break;
    case 0x18:  /* BAR2 */
    case 0x1c:  /* BAR3 */
    case 0x20:  /* BAR4 */
        STORE_LE32(&serial->vconfig[offset], 0);
        break;
    default:
        g_debug("PCI config write @0x%x of %d bytes not handled",
                offset, count);
        break;
    }
}

static ssize_t
vfio_user_serial_access(VuDev *dev, char *buf, size_t count,
                        off_t pos, bool is_write)
{
    VuSerialDev *serial = container_of(dev, VuSerialDev, parent);
    unsigned int index;
    off_t offset;
    int ret = 0;

    index = MTTY_VFIO_PCI_OFFSET_TO_INDEX(pos);
    offset = pos & MTTY_VFIO_PCI_OFFSET_MASK;
    switch (index) {
    case VFIO_PCI_CONFIG_REGION_INDEX:
        g_debug("%s: PCI config space %s at offset 0x%lx",
                __func__, is_write ? "write" : "read", offset);
        if (is_write) {
            handle_pci_cfg_write(serial, offset, buf, count);
        } else {
            memcpy(buf, serial->vconfig + offset, count);
        }
        break;
    case VFIO_PCI_BAR0_REGION_INDEX ... VFIO_PCI_BAR5_REGION_INDEX:
        if (!serial->region_info[index].start)
            vfio_user_serial_read_base(dev);

        if (is_write) {
            g_debug("%s: BAR%d  WR @0x%lx %s val:0x%02x dlab:%d",
                    __func__, index, offset, wr_reg[offset],
                    (uint8_t)*buf, serial->s.dlab);
            /* handle_bar_write(index, serial, offset, buf, count); */
        } else {
            /* handle_bar_read(index, serial, offset, buf, count); */
            g_debug("%s: BAR%d  RD @0x%lx %s val:0x%02x dlab:%d",
                    __func__, index, offset, rd_reg[offset],
                    (uint8_t)*buf, serial->s.dlab);
        }
        break;
    default:
        ret = -1;
        goto accessfailed;
    }

    ret = count;

accessfailed:
    return ret;
}

static ssize_t
vfio_user_serial_read(VuDev *dev, char *buf, size_t count, off_t *ppos)
{
    unsigned int done = 0;
    int ret;

    while (count) {
        size_t filled;

        if (count >= 4 && !(*ppos % 4)) {
            ret = vfio_user_serial_access(dev, buf, 4, *ppos, false);
            if (ret <= 0)
                goto read_err;

            filled = 4;
        } else if (count >= 2 && !(*ppos % 2)) {
            ret = vfio_user_serial_access(dev, buf, 2, *ppos, false);
            if (ret <= 0)
                goto read_err;

            filled = 2;
        } else {
            ret = vfio_user_serial_access(dev, buf, 1, *ppos, false);
            if (ret <= 0)
                goto read_err;

            filled = 1;
        }

        count -= filled;
        done += filled;
        *ppos += filled;
        buf += filled;
    }

    return done;

read_err:
        return -EFAULT;
}

static ssize_t
vfio_user_serial_write(VuDev *dev, const char *buf, size_t count, off_t *ppos)
{
    unsigned int done = 0;
    int ret;

    while (count) {
        size_t filled;

        if (count >= 4 && !(*ppos % 4)) {
            ret = vfio_user_serial_access(dev, (void *)buf, 4, *ppos, true);
            if (ret <= 0)
                goto write_err;

            filled = 4;
        } else if (count >= 2 && !(*ppos % 2)) {
            ret = vfio_user_serial_access(dev, (void *)buf, 2, *ppos, true);
            if (ret <= 0)
                goto write_err;

            filled = 2;
        } else {
            ret = vfio_user_serial_access(dev, (void *)buf, 1, *ppos, true);
            if (ret <= 0)
                goto write_err;

            filled = 1;
        }

        count -= filled;
        done += filled;
        *ppos += filled;
        buf += filled;
    }

    return done;

write_err:
    return -EFAULT;
}

static int
vfio_user_serial_get_device_info(VuDev *dev,
                                 struct vfio_device_info *info)
{
    info->num_regions = VFIO_PCI_NUM_REGIONS;
    info->num_irqs = VFIO_PCI_NUM_IRQS;
    info->flags = VFIO_DEVICE_FLAGS_PCI;

    return 0;
}

static int
vfio_user_serial_get_region_info(VuDev *dev,
                                 struct vfio_region_info *info)
{
    VuSerialDev *serial = container_of(dev, VuSerialDev, parent);

    switch (info->index) {
    case VFIO_PCI_CONFIG_REGION_INDEX:
        info->size = MTTY_CONFIG_SPACE_SIZE;
        break;
    case VFIO_PCI_BAR0_REGION_INDEX:
        info->size = MTTY_IO_BAR_SIZE;
        break;
    default:
        info->size = 0;
        break;
    }

    info->offset = MTTY_VFIO_PCI_INDEX_TO_OFFSET(info->index);
    info->flags = VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE;

    serial->region_info[info->index].size = info->size;
    serial->region_info[info->index].vfio_offset = info->offset;

    return 0;
}

static int
vfio_user_serial_get_irq_info(VuDev *dev, uint32_t index,
                              struct vfio_irq_info *info)
{
    switch (index) {
    case VFIO_PCI_INTX_IRQ_INDEX:
    case VFIO_PCI_MSI_IRQ_INDEX:
    case VFIO_PCI_REQ_IRQ_INDEX:
        break;

    default:
        return -EINVAL;
    }

    info->flags = VFIO_IRQ_INFO_EVENTFD;
    info->count = 1;

    if (index == VFIO_PCI_INTX_IRQ_INDEX) {
        info->flags |= (VFIO_IRQ_INFO_MASKABLE |
                        VFIO_IRQ_INFO_AUTOMASKED);
    } else {
        info->flags |= VFIO_IRQ_INFO_NORESIZE;
    }

    return 0;
}

static int
vfio_user_serial_set_irqs(VuDev *dev, uint32_t index, uint32_t start,
                          int *fds, size_t nfds, uint32_t flags)
{
    int ret = 0;
    VuSerialDev *serial = container_of(dev, VuSerialDev, parent);

    switch (index) {
    case VFIO_PCI_INTX_IRQ_INDEX:
        switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
        case VFIO_IRQ_SET_ACTION_MASK:
        case VFIO_IRQ_SET_ACTION_UNMASK:
            break;
        case VFIO_IRQ_SET_ACTION_TRIGGER: {
            if (flags & VFIO_IRQ_SET_DATA_NONE) {
                g_debug("%s: disable INTx", __func__);
                /* if (serial->intx_evtfd) */
                /*     eventfd_ctx_put(serial->intx_evtfd); */
                break;
            }

            if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
                /* int fd = *(int *)data; */

                /* if (fd > 0) { */
                /*     struct eventfd_ctx *evt; */

                /*     evt = eventfd_ctx_fdget(fd); */
                /*     if (IS_ERR(evt)) { */
                /*         ret = PTR_ERR(evt); */
                /*         break; */
                /*     } */
                /*     serial->intx_evtfd = evt; */
                /*     serial->irq_fd = fd; */
                /*     serial->irq_index = index; */
                /*     break; */
                /* } */
            }
            break;
        }
        }
        break;
    case VFIO_PCI_MSI_IRQ_INDEX:
        switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
        case VFIO_IRQ_SET_ACTION_MASK:
        case VFIO_IRQ_SET_ACTION_UNMASK:
            break;
        case VFIO_IRQ_SET_ACTION_TRIGGER:
            if (flags & VFIO_IRQ_SET_DATA_NONE) {
                /* if (serial->msi_evtfd) */
                /*     eventfd_ctx_put(serial->msi_evtfd); */
                g_debug("%s: disable MSI", __func__);
                serial->irq_index = VFIO_PCI_INTX_IRQ_INDEX;
                break;
            }
            if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
                /* int fd = *(int *)data; */
                /* struct eventfd_ctx *evt; */

                /* if (fd <= 0) */
                /*     break; */

                /* if (serial->msi_evtfd) */
                /*     break; */

                /* evt = eventfd_ctx_fdget(fd); */
                /* if (IS_ERR(evt)) { */
                /*     ret = PTR_ERR(evt); */
                /*     break; */
                /* } */
                /* serial->msi_evtfd = evt; */
                /* serial->irq_fd = fd; */
                /* serial->irq_index = index; */
            }
            break;
    }
    break;
    case VFIO_PCI_MSIX_IRQ_INDEX:
        g_debug("%s: MSIX_IRQ", __func__);
        break;
    case VFIO_PCI_ERR_IRQ_INDEX:
        g_debug("%s: ERR_IRQ", __func__);
        break;
    case VFIO_PCI_REQ_IRQ_INDEX:
        g_debug("%s: REQ_IRQ", __func__);
        break;
    }

    return ret;
}

static int
vfio_user_serial_reset(VuDev *dev)
{
    g_debug("%s: called", __func__);
    return 0;
}

static void
vfio_user_serial_create_config_space(VuSerialDev *serial)
{
    /* PCI dev ID */
    STORE_LE32((uint32_t *) &serial->vconfig[0x0], 0x32534348);

    /* Control: I/O+, Mem-, BusMaster- */
    STORE_LE16((uint16_t *) &serial->vconfig[0x4], 0x0001);

    /* Status: capabilities list absent */
    STORE_LE16((uint16_t *) &serial->vconfig[0x6], 0x0200);

    /* Rev ID */
    serial->vconfig[0x8] =  0x10;

    /* programming interface class : 16550-compatible serial controller */
    serial->vconfig[0x9] =  0x02;

    /* Sub class : 00 */
    serial->vconfig[0xa] =  0x00;

    /* Base class : Simple Communication controllers */
    serial->vconfig[0xb] =  0x07;

    /* base address registers */
    /* BAR0: IO space */
    STORE_LE32((uint32_t *) &serial->vconfig[0x10], 0x000001);
    serial->bar_mask[0] = ~(MTTY_IO_BAR_SIZE) + 1;

    /* Subsystem ID */
    STORE_LE32((uint32_t *) &serial->vconfig[0x2c], 0x32534348);

    serial->vconfig[0x34] =  0x00;   /* Cap Ptr */
    serial->vconfig[0x3d] =  0x01;   /* interrupt pin (INTA#) */

    /* Vendor specific data */
    serial->vconfig[0x40] =  0x23;
    serial->vconfig[0x43] =  0x80;
    serial->vconfig[0x44] =  0x23;
    serial->vconfig[0x48] =  0x23;
    serial->vconfig[0x4c] =  0x23;

    serial->vconfig[0x60] =  0x50;
    serial->vconfig[0x61] =  0x43;
    serial->vconfig[0x62] =  0x49;
    serial->vconfig[0x63] =  0x20;
    serial->vconfig[0x64] =  0x53;
    serial->vconfig[0x65] =  0x65;
    serial->vconfig[0x66] =  0x72;
    serial->vconfig[0x67] =  0x69;
    serial->vconfig[0x68] =  0x61;
    serial->vconfig[0x69] =  0x6c;
    serial->vconfig[0x6a] =  0x2f;
    serial->vconfig[0x6b] =  0x55;
    serial->vconfig[0x6c] =  0x41;
    serial->vconfig[0x6d] =  0x52;
    serial->vconfig[0x6e] =  0x54;
}

static bool
libvfio_user_init_container(libvfio *vfio, libvfio_container *container,
                            Error **errp)
{
    *container = (struct libvfio_container) {
        .vfio = vfio,
    };
    return true;
}

static void
libvfio_user_container_deinit(libvfio_container *container)
{
}

static bool
libvfio_user_container_check_extension(libvfio_container *container,
                                       int ext, Error **errp)
{
    if (ext == VFIO_TYPE1_IOMMU || VFIO_TYPE1v2_IOMMU) {
        return true;
    }

    return false;
}

static bool
libvfio_user_container_set_iommu(libvfio_container *container, int iommu_type,
                                 Error **errp)
{
    return true;
}

static bool
libvfio_user_container_iommu_get_info(libvfio_container *container,
                                      struct vfio_iommu_type1_info *info,
                                      Error **errp)
{
    *info = (struct vfio_iommu_type1_info) {
        .flags = VFIO_IOMMU_INFO_PGSIZES,
        .iova_pgsizes = 4096,
    };
    return false;
}

static bool
libvfio_user_container_iommu_map_dma(libvfio_container *container,
                                     uint64_t vaddr, uint64_t iova,
                                     uint64_t size, uint32_t flags,
                                     Error **errp)
{
    uint64_t offset;
    int fd;

    g_debug("map_dma vaddr:0x%" PRIx64 " iova:0x%" PRIx64
            " size:0x%" PRIx64 " flags:0x%" PRIx32,
            vaddr, iova, size, flags);

    if (!container->vfio->get_mem_fd((void *)(uintptr_t)vaddr,
                                     &offset, &fd, errp)) {
        return false;
    }
    g_debug("map_dma fd:%d, offset:0x%" PRIx64, fd, offset);

    return true;
}

static bool
libvfio_user_container_iommu_unmap_dma(libvfio_container *container,
                                       uint64_t iova, uint64_t size,
                                       uint32_t flags, Error **errp)
{
    g_debug("unmap_dma iova:0x%" PRIx64 " size:0x%" PRIx64 " flags:0x%" PRIx32,
            iova, size, flags);

    return true;
}

static bool
libvfio_user_init_group(libvfio *vfio, libvfio_group *group,
                        int groupid, Error **errp)
{
    *group = (struct libvfio_group) {
        .vfio = vfio,
    };

    return true;
}

static void
libvfio_user_group_deinit(libvfio_group *group)
{
}

static bool
libvfio_user_group_get_device(libvfio_group *group,
                              libvfio_dev *dev, Error **errp)
{
    /* XXX: could learn to lookup a specific device */
    return true;
}

static bool
libvfio_user_group_set_container(libvfio_group *group,
                                 libvfio_container *container,
                                 Error **errp)
{
    return true;
}

static bool
libvfio_user_group_unset_container(libvfio_group *group,
                                   libvfio_container *container,
                                   Error **errp)
{
    return true;
}

static bool
libvfio_user_init_dev(libvfio *vfio, libvfio_dev *dev,
                      const char *path, Error **errp)
{
    /* XXX: could learn to lookup a specific device */
    /* XXX: get device name */
    *dev = (struct libvfio_dev) {
        .name = g_strdup("vfio-user device"),
        .vfio = vfio,
    };

    serial = (struct VuSerialDev) {
        .s.max_fifo_size = MAX_FIFO_SIZE,
    };
    vfio_user_serial_create_config_space(&serial);

    return true;
}

static void
libvfio_user_dev_deinit(libvfio_dev *dev)
{
}

static bool
libvfio_user_dev_reset(libvfio_dev *dev, Error **errp)
{
    int ret = vfio_user_serial_reset(vdev);

    if (ret < 0) {
        error_setg_errno(errp, errno, "failed to rest");
        return false;
    }

    return true;
}

static bool
libvfio_user_dev_set_irqs(libvfio_dev *dev,
                          uint32_t index,
                          uint32_t start,
                          int *fds,
                          size_t nfds,
                          uint32_t flags,
                          Error **errp)
{
    int ret = vfio_user_serial_set_irqs(vdev, index, start, fds, nfds, flags);

    if (ret < 0) {
        error_setg_errno(errp, -ret, "failed to set irqs");
        return false;
    }

    return true;
}

static bool
libvfio_user_dev_get_irq_info(libvfio_dev *dev,
                              uint32_t index,
                              struct vfio_irq_info *irq,
                              Error **errp)
{
    int ret = vfio_user_serial_get_irq_info(vdev, index, irq);

    if (ret < 0) {
        error_setg_errno(errp, -ret, "failed to get irq info");
        return false;
    }

    return true;
}

static bool
libvfio_user_write(libvfio *vfio, vfio_user_msg *msg, Error **errp)
{
    int size = VFIO_USER_HDR_SIZE + msg->size;
    int ret = qemu_chr_fe_write_all(vfio->chr, (uint8_t*)msg, size);

    if (ret != size) {
        error_setg(errp, "failed to write %d bytes, wrote %d", size, ret);
        return false;
    }

    return true;
}

static bool
libvfio_user_read_hdr(libvfio *vfio, vfio_user_msg *msg, Error **errp)
{
    int size = VFIO_USER_HDR_SIZE;
    int ret = qemu_chr_fe_read_all(vfio->chr, (uint8_t*)msg, size);

    if (ret != size) {
        error_setg(errp, "failed to read %d bytes, read %d", size, ret);
        return false;
    }

    return true;
}

static bool
libvfio_user_read_payload(libvfio *vfio, void *payload,
                          size_t size, Error **errp)
{
    int ret = qemu_chr_fe_read_all(vfio->chr, payload, size);

    if (ret != size) {
        error_setg(errp, "failed to read %zu bytes, read %d", size, ret);
        return false;
    }

    return true;
}

static bool
libvfio_user_dev_get_info(libvfio_dev *dev,
                          struct vfio_device_info *info, Error **errp)
{
#if 0
    vfio_user_msg msg = {
        .req = VFIO_USER_REQ_DEV_GET_INFO,
        .size = sizeof(msg.u64),
        .u64 = sizeof(*info),
    };

    if (!libvfio_user_write(dev->vfio, &msg, errp)) {
        return false;
    }
    if (!libvfio_user_read_hdr(dev->vfio, &msg, errp)) {
        return false;
    }
    if (msg.size != sizeof(*info)) {
        error_setg(errp, "unexpected reply length");
        return false;
    }
    if (!libvfio_user_read_payload(dev->vfio, info, sizeof(*info), errp)) {
        return false;
    }
#endif
    vfio_user_serial_get_device_info(vdev, info);

    return true;
}

static bool
libvfio_user_dev_get_region_info(libvfio_dev *dev, int index,
                                 struct vfio_region_info *info, Error **errp)
{
    vfio_user_serial_get_region_info(vdev, info);

    return true;
}

static bool
libvfio_user_dev_get_pci_hot_reset_info(libvfio_dev *dev,
                                        struct vfio_pci_hot_reset_info *info,
                                        Error **errp)
{
    return false;
}

static bool
libvfio_user_dev_pci_hot_reset(libvfio_dev *dev,
                               libvfio_group **groups,
                               size_t ngroups,
                               Error **errp)
{
    return false;
}

static ssize_t
libvfio_user_dev_write(libvfio_dev *dev,
                       const void *buf, size_t size, off_t offset,
                       Error **errp)
{
    ssize_t ret = vfio_user_serial_write(vdev, buf, size, &offset);

    if (ret < 0) {
        error_setg_errno(errp, -ret, "failed during dev_write");
    }

    return ret;
}

static ssize_t
libvfio_user_dev_read(libvfio_dev *dev,
                      void *buf, size_t size, off_t offset,
                      Error **errp)
{
    ssize_t ret = vfio_user_serial_read(vdev, buf, size, &offset);

    if (ret < 0) {
        error_setg_errno(errp, -ret, "failed during dev_read");
    }

    return ret;
}

static void *
libvfio_user_dev_mmap(libvfio_dev *dev,
                      size_t length, int prot, int flags, off_t offset,
                      Error **errp)
{
    return MAP_FAILED;
}

static bool
libvfio_user_dev_unmmap(libvfio_dev *dev,
                        void *addr, size_t length, Error **errp)
{
    return false;
}

static libvfio_ops libvfio_user_ops = {
    .init_container = libvfio_user_init_container,
    .container_deinit = libvfio_user_container_deinit,
    .container_check_extension = libvfio_user_container_check_extension,
    .container_set_iommu = libvfio_user_container_set_iommu,
    .container_iommu_get_info = libvfio_user_container_iommu_get_info,
    .container_iommu_map_dma = libvfio_user_container_iommu_map_dma,
    .container_iommu_unmap_dma = libvfio_user_container_iommu_unmap_dma,
    .init_group = libvfio_user_init_group,
    .group_deinit = libvfio_user_group_deinit,
    .group_set_container = libvfio_user_group_set_container,
    .group_unset_container = libvfio_user_group_unset_container,
    .group_get_device = libvfio_user_group_get_device,
    .init_dev = libvfio_user_init_dev,
    .dev_deinit = libvfio_user_dev_deinit,
    .dev_reset = libvfio_user_dev_reset,
    .dev_set_irqs = libvfio_user_dev_set_irqs,
    .dev_get_irq_info = libvfio_user_dev_get_irq_info,
    .dev_get_info = libvfio_user_dev_get_info,
    .dev_get_region_info = libvfio_user_dev_get_region_info,
    /* .dev_get_pci_hot_reset_info = libvfio_user_dev_get_pci_hot_reset_info, */
    /* .dev_pci_hot_reset = libvfio_user_dev_pci_hot_reset, */
    .dev_write = libvfio_user_dev_write,
    .dev_read = libvfio_user_dev_read,
    .dev_mmap = libvfio_user_dev_mmap,
    .dev_unmmap = libvfio_user_dev_unmmap,
};

bool
libvfio_init_user(libvfio *vfio,
                  CharBackend *chr,
                  libvfio_get_mem_fd *get_mem_fd,
                  Error **errp)
{
    assert(vfio);
    assert(chr);
    assert(get_mem_fd);

    *vfio = (struct libvfio) {
        .chr = chr,
        .get_mem_fd = get_mem_fd,
        .ops = &libvfio_user_ops,
    };

    return true;
}

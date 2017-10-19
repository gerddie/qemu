/*
 * vfio-user-serial sample
 *
 * Copyright (c) 2017 Red Hat, Inc.
 * Copyright (c) 2016, NVIDIA CORPORATION. All rights reserved.
 *
 * Authors:
 *  Marc-André Lureau <mlureau@redhat.com>
 *  Neo Jia <cjia@nvidia.com>
 *  Kirti Wankhede <kwankhede@nvidia.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 * Sample vfio-user device that simulates serial port over PCI card.
 */

#include "libvfio-user-glib.h"
#include <glib/gstdio.h>
#include <glib-unix.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>

#include <linux/pci.h>
#include <linux/serial_reg.h>
#include <sys/eventfd.h>

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

#ifndef container_of
#define container_of(ptr, type, member) ({                          \
            const typeof(((type *) 0)->member) *__mptr = (ptr);     \
            (type *) ((char *) __mptr - offsetof(type, member));})
#endif

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
    VugDev parent;

    GMainLoop *loop;
    int intx_evtfd;
    int msi_evtfd;
    int irq_index;
    char vconfig[MTTY_CONFIG_SPACE_SIZE];
    struct region_info region_info[VFIO_PCI_NUM_REGIONS];
    uint32_t bar_mask[VFIO_PCI_NUM_REGIONS];
    struct serial_port s;
    struct vfio_device_info dev_info;
} VuSerialDev;

static int
vfio_user_serial_trigger_interrupt(VuSerialDev *serial)
{
    int ret = -1;

    if ((serial->irq_index == VFIO_PCI_MSI_IRQ_INDEX) &&
        (!serial->msi_evtfd)) {
        return -EINVAL;
    } else if ((serial->irq_index == VFIO_PCI_INTX_IRQ_INDEX) &&
         (!serial->intx_evtfd)) {
        g_debug("%s: Intr eventfd not found", __func__);
        return -EINVAL;
    }

    if (serial->irq_index == VFIO_PCI_MSI_IRQ_INDEX) {
        ret = eventfd_write(serial->msi_evtfd, 1);
    } else {
        ret = eventfd_write(serial->intx_evtfd, 1);
    }

    g_debug("Intx triggered");
    if (ret < 0) {
        g_critical("%s: eventfd signal failed (%d)", __func__, ret);
    }

    return ret;
}

static void
vfio_user_serial_read_base(VuDev *dev)
{
    VuSerialDev *serial = container_of(dev, VuSerialDev, parent.parent);
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

static void
handle_pci_cfg_write(VuSerialDev *serial, uint16_t offset,
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

static void
handle_bar_read(VuSerialDev *serial, unsigned int index,
                uint16_t offset, char *buf, uint32_t count)
{
    /* Handle read requests by guest */
    switch (offset) {
    case UART_RX:
        /* if DLAB set, data is LSB of divisor */
        if (serial->s.dlab) {
            *buf  = (uint8_t)serial->s.divisor;
            break;
        }

        /* return data in tx buffer */
        if (serial->s.rxtx.head != serial->s.rxtx.tail) {
            *buf = serial->s.rxtx.fifo[serial->s.rxtx.tail];
            serial->s.rxtx.count--;
            CIRCULAR_BUF_INC_IDX(serial->s.rxtx.tail);
        }

        if (serial->s.rxtx.head == serial->s.rxtx.tail) {
            /*
             *  Trigger interrupt if tx buffer empty interrupt is
             *  enabled and fifo is empty
             */
            g_debug("Serial port %d: Buffer Empty", index);
            if (serial->s.uart_reg[UART_IER] & UART_IER_THRI) {
                vfio_user_serial_trigger_interrupt(serial);
            }
        }

        break;
    case UART_IER:
        if (serial->s.dlab) {
            *buf = (uint8_t)(serial->s.divisor >> 8);
            break;
        }
        *buf = serial->s.uart_reg[offset] & 0x0f;
        break;

    case UART_IIR: {
        uint8_t ier = serial->s.uart_reg[UART_IER];
        *buf = 0;

        /* Interrupt priority 1: Parity, overrun, framing or break */
        if ((ier & UART_IER_RLSI) && serial->s.overrun) {
            *buf |= UART_IIR_RLSI;
        }

        /* Interrupt priority 2: Fifo trigger level reached */
        if ((ier & UART_IER_RDI) &&
            (serial->s.rxtx.count == serial->s.intr_trigger_level)) {
            *buf |= UART_IIR_RDI;
        }

        /* Interrupt priotiry 3: transmitter holding register empty */
        if ((ier & UART_IER_THRI) &&
            (serial->s.rxtx.head == serial->s.rxtx.tail)) {
            *buf |= UART_IIR_THRI;
        }

        /* Interrupt priotiry 4: Modem status: CTS, DSR, RI or DCD  */
        if ((ier & UART_IER_MSI) &&
            (serial->s.uart_reg[UART_MCR] & (UART_MCR_RTS | UART_MCR_DTR))) {
            *buf |= UART_IIR_MSI;
        }

        /* bit0: 0=> interrupt pending, 1=> no interrupt is pending */
        if (*buf == 0) {
            *buf = UART_IIR_NO_INT;
        }

        /* set bit 6 & 7 to be 16550 compatible */
        *buf |= 0xC0;
    }
    break;

    case UART_LCR:
    case UART_MCR:
        *buf = serial->s.uart_reg[offset];
        break;

    case UART_LSR: {
        uint8_t lsr = 0;

        /* atleast one char in FIFO */
        if (serial->s.rxtx.head != serial->s.rxtx.tail) {
            lsr |= UART_LSR_DR;
        }

        /* if FIFO overrun */
        if (serial->s.overrun) {
            lsr |= UART_LSR_OE;
        }

        /* transmit FIFO empty and tramsitter empty */
        if (serial->s.rxtx.head == serial->s.rxtx.tail) {
            lsr |= UART_LSR_TEMT | UART_LSR_THRE;
        }

        *buf = lsr;
        break;
    }

    case UART_MSR:
        *buf = UART_MSR_DSR | UART_MSR_DDSR | UART_MSR_DCD;

        /* if AFE is 1 and FIFO have space, set CTS bit */
        if ((serial->s.uart_reg[UART_MCR] & UART_MCR_AFE) &&
            serial->s.rxtx.count < serial->s.max_fifo_size) {
            *buf |= UART_MSR_CTS | UART_MSR_DCTS;
        } else {
            *buf |= UART_MSR_CTS | UART_MSR_DCTS;
        }

        break;

    case UART_SCR:
        *buf = serial->s.uart_reg[offset];
        break;

    default:
        break;
    }
}

static void
handle_bar_write(VuSerialDev *serial, unsigned int index,
                 uint16_t offset, char *buf, uint32_t count)
{
    uint8_t data = *buf;

    /* Handle data written by guest */
    switch (offset) {
    case UART_TX:
        /* if DLAB set, data is LSB of divisor */
        if (serial->s.dlab) {
            serial->s.divisor |= data;
            break;
        }

        /* save in TX buffer */
        if (serial->s.rxtx.count < serial->s.max_fifo_size) {
            serial->s.rxtx.fifo[serial->s.rxtx.head] = data;
            serial->s.rxtx.count++;
            CIRCULAR_BUF_INC_IDX(serial->s.rxtx.head);
            serial->s.overrun = false;

            /*
             * Trigger interrupt if receive data interrupt is
             * enabled and fifo reached trigger level
             */
            if ((serial->s.uart_reg[UART_IER] & UART_IER_RDI) &&
               (serial->s.rxtx.count == serial->s.intr_trigger_level)) {
                /* trigger interrupt */
                g_debug("Serial port %d: Fifo level trigger", index);
                vfio_user_serial_trigger_interrupt(serial);
            }
        } else {
            g_debug("Serial port %d: Buffer Overflow", index);
            serial->s.overrun = true;

            /*
             * Trigger interrupt if receiver line status interrupt
             * is enabled
             */
            if (serial->s.uart_reg[UART_IER] & UART_IER_RLSI) {
                vfio_user_serial_trigger_interrupt(serial);
            }
        }
        break;

    case UART_IER:
        /* if DLAB set, data is MSB of divisor */
        if (serial->s.dlab) {
            serial->s.divisor |= (uint16_t)data << 8;
        } else {
            serial->s.uart_reg[offset] = data;
            if ((data & UART_IER_THRI) &&
                (serial->s.rxtx.head == serial->s.rxtx.tail)) {
                g_debug("Serial port %d: IER_THRI write", index);
                vfio_user_serial_trigger_interrupt(serial);
            }
        }
        break;

    case UART_FCR:
        serial->s.fcr = data;

        if (data & (UART_FCR_CLEAR_RCVR | UART_FCR_CLEAR_XMIT)) {
            /* clear loop back FIFO */
            serial->s.rxtx.count = 0;
            serial->s.rxtx.head = 0;
            serial->s.rxtx.tail = 0;
        }

        switch (data & UART_FCR_TRIGGER_MASK) {
        case UART_FCR_TRIGGER_1:
            serial->s.intr_trigger_level = 1;
            break;

        case UART_FCR_TRIGGER_4:
            serial->s.intr_trigger_level = 4;
            break;

        case UART_FCR_TRIGGER_8:
            serial->s.intr_trigger_level = 8;
            break;

        case UART_FCR_TRIGGER_14:
            serial->s.intr_trigger_level = 14;
            break;
        }

        /*
         * Set trigger level to 1 otherwise or  implement timer with
         * timeout of 4 characters and on expiring that timer set
         * Recevice data timeout in IIR register
         */
        serial->s.intr_trigger_level = 1;
        if (data & UART_FCR_ENABLE_FIFO) {
            serial->s.max_fifo_size = MAX_FIFO_SIZE;
        } else {
            serial->s.max_fifo_size = 1;
            serial->s.intr_trigger_level = 1;
        }

        break;

    case UART_LCR:
        if (data & UART_LCR_DLAB) {
            serial->s.dlab = true;
            serial->s.divisor = 0;
        } else {
            serial->s.dlab = false;
        }

        serial->s.uart_reg[offset] = data;
        break;

    case UART_MCR:
        serial->s.uart_reg[offset] = data;

        if ((serial->s.uart_reg[UART_IER] & UART_IER_MSI) &&
            (data & UART_MCR_OUT2)) {
            g_debug("Serial port %d: MCR_OUT2 write", index);
            vfio_user_serial_trigger_interrupt(serial);
        }

        if ((serial->s.uart_reg[UART_IER] & UART_IER_MSI) &&
            (data & (UART_MCR_RTS | UART_MCR_DTR))) {
            g_debug("Serial port %d: MCR RTS/DTR write", index);
            vfio_user_serial_trigger_interrupt(serial);
        }
        break;

    case UART_LSR:
    case UART_MSR:
        /* do nothing */
        break;

    case UART_SCR:
        serial->s.uart_reg[offset] = data;
        break;

    default:
        break;
    }
}

static ssize_t
vfio_user_serial_access(VuDev *dev, char *buf, size_t count,
                        off_t pos, bool is_write)
{
    VuSerialDev *serial = container_of(dev, VuSerialDev, parent.parent);
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
            handle_bar_write(serial, index, offset, buf, count);
        } else {
            handle_bar_read(serial, index, offset, buf, count);
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
vfio_user_serial_get_region_info(VuDev *dev, int index,
                                 struct vfio_region_info *info)
{
    VuSerialDev *serial = container_of(dev, VuSerialDev, parent.parent);

    if (index >= VFIO_PCI_NUM_REGIONS)
        return -EINVAL;

    switch (index) {
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

    info->offset = MTTY_VFIO_PCI_INDEX_TO_OFFSET(index);
    info->flags = VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE;

    serial->region_info[index].size = info->size;
    serial->region_info[index].vfio_offset = info->offset;

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
    VuSerialDev *serial = container_of(dev, VuSerialDev, parent.parent);

    switch (index) {
    case VFIO_PCI_INTX_IRQ_INDEX:
        switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
        case VFIO_IRQ_SET_ACTION_MASK:
        case VFIO_IRQ_SET_ACTION_UNMASK:
            break;
        case VFIO_IRQ_SET_ACTION_TRIGGER: {
            if (flags & VFIO_IRQ_SET_DATA_NONE) {
                g_debug("%s: disable INTx", __func__);
                if (serial->intx_evtfd >= 0) {
                    close(serial->intx_evtfd);
                    serial->intx_evtfd = -1;
                }
                break;
            }

            if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
                if (nfds != 1 || serial->intx_evtfd >= 0) {
                    return -EINVAL;
                }

                serial->intx_evtfd = *fds;
                serial->irq_index = index;
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
                if (serial->msi_evtfd >= 0) {
                    close(serial->msi_evtfd);
                    serial->msi_evtfd = -1;
                }
                g_debug("%s: disable MSI", __func__);
                serial->irq_index = VFIO_PCI_INTX_IRQ_INDEX;
                break;
            }
            if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
                if (nfds != 1 || serial->msi_evtfd >= 0) {
                    return -EINVAL;
                }

                serial->msi_evtfd = *fds;
                serial->irq_index = index;
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

static void
vfio_user_serial_panic(VuDev *dev, const char *err)
{
    g_error("%s\n", err);
}

static int
unix_sock_new(const char *path)
{
    int sock;
    struct sockaddr_un un;
    size_t len;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock <= 0) {
        perror("socket");
        return -1;
    }

    un.sun_family = AF_UNIX;
    snprintf(un.sun_path, sizeof(un.sun_path), "%s", path);
    len = sizeof(un.sun_family) + strlen(un.sun_path);

    g_unlink(path);
    if (bind(sock, (struct sockaddr *)&un, len) < 0) {
        perror("bind");
        goto fail;
    }

    if (listen(sock, 1) < 0) {
        perror("listen");
        goto fail;
    }

    return sock;

fail:
    close(sock);

    return -1;
}

static VuDevIface vfio_user_serial_iface = {
    .get_device_info = vfio_user_serial_get_device_info,
    .read = vfio_user_serial_read,
    .write = vfio_user_serial_write,
    .get_region_info = vfio_user_serial_get_region_info,
    .get_irq_info = vfio_user_serial_get_irq_info,
    .set_irqs = vfio_user_serial_set_irqs,
    .reset = vfio_user_serial_reset,
};

int
main(int argc, char *argv[])
{
    int lsock, csock, ret = 1;
    VuSerialDev serial = {
        .s.max_fifo_size = MAX_FIFO_SIZE,
        .intx_evtfd = -1,
        .msi_evtfd = -1,
    };

    if (argc != 2) {
        g_printerr("%s <socket-path>\n", argv[0]);
        goto out;
    }
    lsock = unix_sock_new(argv[1]);
    if (lsock < 0) {
        goto out;
    }

    csock = accept(lsock, NULL, NULL);
    if (csock < 0) {
        perror("accept");
        goto out;
    }

    vfio_user_serial_create_config_space(&serial);

    serial.loop = g_main_loop_new(NULL, FALSE);

    vug_init(&serial.parent, csock,
             vfio_user_serial_panic, &vfio_user_serial_iface);

    g_main_loop_run(serial.loop);

    vug_deinit(&serial.parent);

    ret = 0;

out:
    if (serial.loop) {
        g_main_loop_unref(serial.loop);
    }
    if (csock >= 0) {
        close(csock);
    }
    if (lsock >= 0) {
        close(lsock);
    }

    return ret;
}

/*
 * DMA memory preregistration
 *
 * Authors:
 *  Alexey Kardashevskiy <aik@ozlabs.ru>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "cpu.h"

#include "hw/vfio/vfio-common.h"
#include "hw/vfio/libvfio.h"
#include "hw/hw.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "trace.h"

static bool vfio_prereg_listener_skipped_section(MemoryRegionSection *section)
{
    if (memory_region_is_iommu(section->mr)) {
        hw_error("Cannot possibly preregister IOMMU memory");
    }

    return !memory_region_is_ram(section->mr) ||
            memory_region_is_ram_device(section->mr);
}

static void *vfio_prereg_gpa_to_vaddr(MemoryRegionSection *section, hwaddr gpa)
{
    return memory_region_get_ram_ptr(section->mr) +
        section->offset_within_region +
        (gpa - section->offset_within_address_space);
}

static void vfio_prereg_listener_region_add(MemoryListener *listener,
                                            MemoryRegionSection *section)
{
    VFIOContainer *container = container_of(listener, VFIOContainer,
                                            prereg_listener);
    const hwaddr gpa = section->offset_within_address_space;
    hwaddr end;
    int ret;
    hwaddr page_mask = qemu_real_host_page_mask;
    uint64_t vaddr, size;

    if (vfio_prereg_listener_skipped_section(section)) {
        trace_vfio_prereg_listener_region_add_skip(
                section->offset_within_address_space,
                section->offset_within_address_space +
                int128_get64(int128_sub(section->size, int128_one())));
        return;
    }

    if (unlikely((section->offset_within_address_space & ~page_mask) ||
                 (section->offset_within_region & ~page_mask) ||
                 (int128_get64(section->size) & ~page_mask))) {
        error_report("%s received unaligned region", __func__);
        return;
    }

    end = section->offset_within_address_space + int128_get64(section->size);
    if (gpa >= end) {
        return;
    }

    memory_region_ref(section->mr);

    vaddr = (uintptr_t) vfio_prereg_gpa_to_vaddr(section, gpa);
    size = end - gpa;
    ret = libvfio_container_iommu_spapr_register_memory(
        &container->libvfio_container,
        vaddr, size, 0, NULL);

    trace_vfio_prereg_register(vaddr, size, ret);
    if (!ret) {
        /*
         * On the initfn path, store the first error in the container so we
         * can gracefully fail.  Runtime, there's not much we can do other
         * than throw a hardware error.
         */
        if (!container->initialized) {
            if (!container->error) {
                container->error = -1;
            }
        } else {
            hw_error("vfio: Memory registering failed, unable to continue");
        }
    }
}

static void vfio_prereg_listener_region_del(MemoryListener *listener,
                                            MemoryRegionSection *section)
{
    VFIOContainer *container = container_of(listener, VFIOContainer,
                                            prereg_listener);
    const hwaddr gpa = section->offset_within_address_space;
    hwaddr end;
    int ret;
    hwaddr page_mask = qemu_real_host_page_mask;
    uint64_t vaddr, size;

    if (vfio_prereg_listener_skipped_section(section)) {
        trace_vfio_prereg_listener_region_del_skip(
                section->offset_within_address_space,
                section->offset_within_address_space +
                int128_get64(int128_sub(section->size, int128_one())));
        return;
    }

    if (unlikely((section->offset_within_address_space & ~page_mask) ||
                 (section->offset_within_region & ~page_mask) ||
                 (int128_get64(section->size) & ~page_mask))) {
        error_report("%s received unaligned region", __func__);
        return;
    }

    end = section->offset_within_address_space + int128_get64(section->size);
    if (gpa >= end) {
        return;
    }

    vaddr = (uintptr_t) vfio_prereg_gpa_to_vaddr(section, gpa);
    size = end - gpa;
    ret = libvfio_container_iommu_spapr_unregister_memory(
        &container->libvfio_container, vaddr, size, 0, NULL);

    trace_vfio_prereg_unregister(vaddr, size, ret);
}

const MemoryListener vfio_prereg_listener = {
    .region_add = vfio_prereg_listener_region_add,
    .region_del = vfio_prereg_listener_region_del,
};

int vfio_spapr_create_window(VFIOContainer *container,
                             MemoryRegionSection *section,
                             hwaddr *pgsize)
{
    Error *err = NULL;
    IOMMUMemoryRegion *iommu_mr = IOMMU_MEMORY_REGION(section->mr);
    unsigned pagesize = memory_region_iommu_get_min_page_size(iommu_mr);
    unsigned entries, pages, window_size, page_shift, levels;
    uint64_t start_addr;

    /*
     * FIXME: For VFIO iommu types which have KVM acceleration to
     * avoid bouncing all map/unmaps through qemu this way, this
     * would be the right place to wire that up (tell the KVM
     * device emulation the VFIO iommu handles to use).
     */
    window_size = int128_get64(section->size);
    page_shift = ctz64(pagesize);
    /*
     * SPAPR host supports multilevel TCE tables, there is some
     * heuristic to decide how many levels we want for our table:
     * 0..64 = 1; 65..4096 = 2; 4097..262144 = 3; 262145.. = 4
     */
    entries = window_size >> page_shift;
    pages = MAX((entries * sizeof(uint64_t)) / getpagesize(), 1);
    pages = MAX(pow2ceil(pages), 1); /* Round up */
    levels = ctz64(pages) / 6 + 1;

    if (!libvfio_container_iommu_spapr_tce_create(
            &container->libvfio_container,
            page_shift, window_size, levels, 0, &start_addr,
            &err)) {
        error_report_err(err);
        return -1;
    }

    if (start_addr != section->offset_within_address_space) {
        vfio_spapr_remove_window(container, start_addr);

        error_report("Host doesn't support DMA window at %"HWADDR_PRIx", must be %"PRIx64,
                     section->offset_within_address_space, start_addr);
        return -EINVAL;
    }
    trace_vfio_spapr_create_window(page_shift, window_size, start_addr);
    *pgsize = pagesize;

    return 0;
}

int vfio_spapr_remove_window(VFIOContainer *container,
                             hwaddr offset_within_address_space)
{
    Error *err = NULL;

    if (!libvfio_container_iommu_spapr_tce_remove(&container->libvfio_container,
                                                  offset_within_address_space,
                                                  &err)) {
        error_report_err(err);
        return -1;
    }

    trace_vfio_spapr_remove_window(offset_within_address_space);

    return 0;
}

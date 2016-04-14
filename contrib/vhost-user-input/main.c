#include <glib.h>
#include <linux/input.h>

#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "qemu/bswap.h"
#include "contrib/libvhost-user/libvhost-user.h"
#include "standard-headers/linux/virtio_input.h"

typedef struct virtio_input_event virtio_input_event;
typedef struct virtio_input_config virtio_input_config;

typedef struct VuInput {
    VuDev dev;
    GSource *watches[16];
    int evdevfd;
    GArray *config;
    virtio_input_event *queue;
    uint32_t qindex, qsize;
} VuInput;

static void vi_input_send(VuInput *vi, struct virtio_input_event *event)
{
    VuDev *dev = &vi->dev;
    VuVirtq *vq = vu_get_queue(dev, 0);
    VuVirtqElement *elem;
    unsigned have, need;
    int i, len;

    /* queue up events ... */
    if (vi->qindex == vi->qsize) {
        vi->qsize++;
        vi->queue = realloc(vi->queue, vi->qsize *
                                sizeof(virtio_input_event));
    }
    vi->queue[vi->qindex++] = *event;

    /* ... until we see a report sync ... */
    if (event->type != htole16(EV_SYN) ||
        event->code != htole16(SYN_REPORT)) {
        return;
    }

    /* ... then check available space ... */
    need = sizeof(virtio_input_event) * vi->qindex;
    vu_queue_get_avail_bytes(dev, vq, &have, NULL, need, 0);
    if (have < need) {
        vi->qindex = 0;
        g_warning("ENOSPC in vq, dropping events");
        return;
    }

    /* ... and finally pass them to the guest */
    for (i = 0; i < vi->qindex; i++) {
        elem = vu_queue_pop(dev, vq, sizeof(VuVirtqElement));
        if (!elem) {
            /* should not happen, we've checked for space beforehand */
            g_warning("%s: Huh?  No vq elem available ...\n", __func__);
            return;
        }
        len = iov_from_buf(elem->in_sg, elem->in_num,
                           0, vi->queue + i, sizeof(virtio_input_event));
        vu_queue_push(dev, vq, elem, len);
        g_free(elem);
    }
    vu_queue_notify(&vi->dev, vq);
    vi->qindex = 0;
}

static void
vi_evdev_watch(VuDev *dev, int condition, void *data)
{
    VuInput *vi = data;
    int fd = vi->evdevfd;

    g_debug("Got evdev condition %x", condition);

    struct virtio_input_event virtio;
    struct input_event evdev;
    int rc;

    for (;;) {
        rc = read(fd, &evdev, sizeof(evdev));
        if (rc != sizeof(evdev)) {
            break;
        }

        g_debug("input %d %d %d", evdev.type, evdev.code, evdev.value);

        virtio.type  = htole16(evdev.type);
        virtio.code  = htole16(evdev.code);
        virtio.value = htole32(evdev.value);
        vi_input_send(vi, &virtio);
    }
}

static void vi_handle_sts(VuDev *dev, int qidx)
{
    VuInput *vi = container_of(dev, VuInput, dev);
    VuVirtq *vq = vu_get_queue(dev, qidx);
    virtio_input_event event;
    VuVirtqElement *elem;
    int len;

    g_debug("%s", __func__);

    for (;;) {
        elem = vu_queue_pop(dev, vq, sizeof(VuVirtqElement));
        if (!elem) {
            break;
        }

        memset(&event, 0, sizeof(event));
        len = iov_to_buf(elem->out_sg, elem->out_num,
                         0, &event, sizeof(event));
        g_debug("TODO handle status %d %p", len, elem);
        vu_queue_push(dev, vq, elem, len);
        g_free(elem);
    }

    vu_queue_notify(&vi->dev, vq);
}

static void
vi_panic(VuDev *dev, const char *msg)
{
    g_critical("%s\n", msg);
    exit(1);
}

typedef struct Watch {
    GSource       source;
    GIOCondition  condition;
    gpointer      tag;
    VuDev        *dev;
    guint         id;
} Watch;

static GIOCondition
vu_to_gio_condition(int condition)
{
    return (condition & VU_WATCH_IN ? G_IO_IN : 0) |
           (condition & VU_WATCH_OUT ? G_IO_OUT : 0) |
           (condition & VU_WATCH_PRI ? G_IO_PRI : 0) |
           (condition & VU_WATCH_ERR ? G_IO_ERR : 0) |
           (condition & VU_WATCH_HUP ? G_IO_HUP : 0);
}

static GIOCondition
vu_from_gio_condition(int condition)
{
    return (condition & G_IO_IN ? VU_WATCH_IN : 0) |
           (condition & G_IO_OUT ? VU_WATCH_OUT : 0) |
           (condition & G_IO_PRI ? VU_WATCH_PRI : 0) |
           (condition & G_IO_ERR ? VU_WATCH_ERR : 0) |
           (condition & G_IO_HUP ? VU_WATCH_HUP : 0);
}

static gboolean
watch_check(GSource *source)
{
    Watch *watch = (Watch *)source;
    GIOCondition poll_condition = g_source_query_unix_fd(source, watch->tag);

    return poll_condition & watch->condition;
}

static gboolean
watch_dispatch(GSource *source,
               GSourceFunc callback,
               gpointer user_data)

{
    vu_watch_cb func = (vu_watch_cb)callback;
    Watch *watch = (Watch *)source;
    GIOCondition poll_condition = g_source_query_unix_fd(source, watch->tag);
    int cond = vu_from_gio_condition(poll_condition & watch->condition);

    (*func) (watch->dev, cond, user_data);

    return G_SOURCE_CONTINUE;
}

static GSourceFuncs watch_funcs = {
    .check = watch_check,
    .dispatch = watch_dispatch,
};

static void
set_fd_handler(VuDev *dev, int fd, GIOCondition condition,
               vu_watch_cb cb, void *data)
{
    VuInput *vi = container_of(dev, VuInput, dev);
    Watch *watch;
    GSource *s;

    g_assert_cmpint(fd, <, G_N_ELEMENTS(vi->watches));

    s = vi->watches[fd];
    if (cb) {
        if (!s) {
            s = g_source_new(&watch_funcs, sizeof(Watch));
            watch = (Watch *)s;
            watch->dev = dev;
            watch->condition = condition;
            watch->tag =
                g_source_add_unix_fd(s, fd, condition);
            watch->id = g_source_attach(s, NULL);
            vi->watches[fd] = s;
        } else {
            watch = (Watch *)s;
            g_source_modify_unix_fd(s, watch->tag, condition);
        }

        g_source_set_callback(s, (GSourceFunc)cb, data, NULL);
    } else if (s) {
        watch = (Watch *)s;
        g_source_remove_unix_fd(s, watch->tag);
        g_source_unref(s);
        g_source_remove(watch->id);
        vi->watches[fd] = NULL;
    }
}

static void
vi_add_watch(VuDev *dev, int fd, int condition,
             vu_watch_cb cb, void *data)
{
    set_fd_handler(dev, fd, vu_to_gio_condition(condition), cb, data);
}

static void
vi_remove_watch(VuDev *dev, int fd)
{
    set_fd_handler(dev, fd, 0, NULL, NULL);
}

static void
vi_queue_set_started(VuDev *dev, int qidx, bool started)
{
    VuInput *vi = container_of(dev, VuInput, dev);
    VuVirtq *vq = vu_get_queue(dev, qidx);

    g_debug("queue started %d:%d", qidx, started);

    if (qidx == 0) {
        set_fd_handler(dev, vi->evdevfd, G_IO_IN,
                       started ? vi_evdev_watch : NULL, vi);
    } else {
        vu_set_queue_handler(dev, vq, started ? vi_handle_sts : NULL);
    }
}

static void
vi_vhost_watch(VuDev *dev, int condition, void *data)
{
    vu_dispatch(dev);
}

static int
vi_process_msg(VuDev *dev, VhostUserMsg *vmsg, int *do_reply)
{
    VuInput *vi = container_of(dev, VuInput, dev);

    switch (vmsg->request) {
    case VHOST_USER_INPUT_GET_CONFIG:
        vmsg->size = vi->config->len * sizeof(virtio_input_config);
        vmsg->data = g_memdup(vi->config->data, vmsg->size);
        *do_reply = true;
        return 1;
    default:
        return 0;
    }
}

static const VuDevIface vuiface = {
    .queue_set_started = vi_queue_set_started,
    .process_msg = vi_process_msg,
};

static void
vi_bits_config(VuInput *vi, int type, int count)
{
    virtio_input_config bits;
    int rc, i, size = 0;

    memset(&bits, 0, sizeof(bits));
    rc = ioctl(vi->evdevfd, EVIOCGBIT(type, count / 8), bits.u.bitmap);
    if (rc < 0) {
        return;
    }

    for (i = 0; i < count / 8; i++) {
        if (bits.u.bitmap[i]) {
            size = i + 1;
        }
    }
    if (size == 0) {
        return;
    }

    bits.select = VIRTIO_INPUT_CFG_EV_BITS;
    bits.subsel = type;
    bits.size   = size;
    g_array_append_val(vi->config, bits);
}

int
main(int argc, char *argv[])
{
    GMainLoop *loop = NULL;
    VuInput vi = { 0, };
    int rc, ver;
    virtio_input_config id;
    struct input_id ids;

    if (argc != 2) {
        g_error("evdev path argument required");
    }

    vi.evdevfd = open(argv[1], O_RDWR);
    if (vi.evdevfd < 0) {
        g_error("Failed to open evdev: %s", g_strerror(errno));
    }

    rc = ioctl(vi.evdevfd, EVIOCGVERSION, &ver);
    if (rc < 0) {
        g_error("%s: is not an evdev device", argv[1]);
    }

    rc = ioctl(vi.evdevfd, EVIOCGRAB, 1);
    if (rc < 0) {
        g_error("Failed to grab device");
    }

    vi.config = g_array_new(false, false, sizeof(virtio_input_config));
    memset(&id, 0, sizeof(id));
    ioctl(vi.evdevfd, EVIOCGNAME(sizeof(id.u.string) - 1), id.u.string);
    id.select = VIRTIO_INPUT_CFG_ID_NAME;
    id.size = strlen(id.u.string);
    g_array_append_val(vi.config, id);

    if (ioctl(vi.evdevfd, EVIOCGID, &ids) == 0) {
        memset(&id, 0, sizeof(id));
        id.select = VIRTIO_INPUT_CFG_ID_DEVIDS;
        id.size = sizeof(struct virtio_input_devids);
        id.u.ids.bustype = cpu_to_le16(ids.bustype);
        id.u.ids.vendor  = cpu_to_le16(ids.vendor);
        id.u.ids.product = cpu_to_le16(ids.product);
        id.u.ids.version = cpu_to_le16(ids.version);
        g_array_append_val(vi.config, id);
    }

    vi_bits_config(&vi, EV_KEY, KEY_CNT);
    vi_bits_config(&vi, EV_REL, REL_CNT);
    vi_bits_config(&vi, EV_ABS, ABS_CNT);
    vi_bits_config(&vi, EV_MSC, MSC_CNT);
    vi_bits_config(&vi, EV_SW,  SW_CNT);
    g_debug("config length: %u", vi.config->len);

    vu_init(&vi.dev, 3, vi_panic, vi_add_watch, vi_remove_watch, &vuiface);
    set_fd_handler(&vi.dev, 3, G_IO_IN | G_IO_HUP, vi_vhost_watch, NULL);

    loop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(loop);
    g_main_loop_unref(loop);

    return 0;
}

/*
 * GCoroutine wrapper
 *
 * Copyright (C) 2014  Marc-André Lureau <marcandre.lureau@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include <gcoroutine.h>
#include "qemu-common.h"
#include "block/coroutine_int.h"

Coroutine *qemu_coroutine_self(void)
{
    return (Coroutine *)g_coroutine_self();
}

bool qemu_in_coroutine(void)
{
    return g_in_coroutine();
}

void qemu_co_queue_init(CoQueue *queue)
{
    g_co_queue_init(queue);
}

void coroutine_fn qemu_co_queue_wait(CoQueue *queue)
{
    g_co_queue_yield(queue, NULL);
}

bool coroutine_fn qemu_co_queue_next(CoQueue *queue)
{
    return g_co_queue_schedule(queue, 1) == 1;
}

void coroutine_fn qemu_co_queue_restart_all(CoQueue *queue)
{
    g_co_queue_schedule(queue, -1);
}

bool qemu_co_enter_next(CoQueue *queue)
{
    if (g_co_queue_is_empty(queue))
        return false;

    g_co_queue_resume_head(queue, NULL);

    return true;
}

bool qemu_co_queue_empty(CoQueue *queue)
{
    return g_co_queue_is_empty(queue);
}

void qemu_co_mutex_init(CoMutex *mutex)
{
    g_co_mutex_init(mutex);
}

void coroutine_fn qemu_co_mutex_lock(CoMutex *mutex)
{
    g_co_mutex_lock(mutex);
}

void coroutine_fn qemu_co_mutex_unlock(CoMutex *mutex)
{
    g_co_mutex_unlock(mutex);
}

void qemu_co_rwlock_init(CoRwlock *lock)
{
    g_co_rw_lock_init(lock);
}

void qemu_co_rwlock_rdlock(CoRwlock *lock)
{
    g_co_rw_lock_reader_lock(lock);
}

void qemu_co_rwlock_unlock(CoRwlock *lock)
{
    if (lock->writer)
        g_co_rw_lock_writer_unlock(lock);
    else
        g_co_rw_lock_reader_unlock(lock);
}

void qemu_co_rwlock_wrlock(CoRwlock *lock)
{
    g_co_rw_lock_writer_lock(lock);
}

static gboolean coroutine_end_cb(gpointer data)
{
    GCoroutine *co = data;

    g_coroutine_unref(co);

    return FALSE;
}

static gpointer coroutine_func(gpointer data)
{
    CoroutineEntry *entry = data;

    data = g_coroutine_yield(NULL);

    entry(data);

    g_idle_add(coroutine_end_cb, g_coroutine_self());

    return NULL;
}

Coroutine *qemu_coroutine_create(CoroutineEntry *entry)
{
    GCoroutine *co = g_coroutine_new(coroutine_func);

    if (!co)
        return NULL;

    g_coroutine_resume(co, entry);

    return (Coroutine*)co;
}

void qemu_coroutine_enter(Coroutine *co, void *opaque)
{
    g_coroutine_resume((GCoroutine*)co, opaque);
}

void coroutine_fn qemu_coroutine_yield(void)
{
    g_coroutine_yield(NULL);
}

void qemu_coroutine_adjust_pool_size(int n)
{
    g_warning("no pool yet");
}

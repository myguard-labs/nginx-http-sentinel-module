/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_shm.c — rbtree + slab + LRU shared-memory zone for sentinel.
 * Absorbed from ngx_http_error_abuse_module (init_zone, rbtree_insert patterns).
 * No persistence, no Redis, no thread-pool — pure in-process shmem.
 */

#include "sentinel.h"

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

/* Return pointer to the event-timestamp array that lives after key bytes.
 * The ring holds time_t (8-byte) values, so it must start on an 8-byte
 * boundary. The slab allocator returns 8-aligned node pointers, but the
 * data[] member itself sits at a 4-aligned offset (the trailing
 * cs_action/key_len fields), and key_len is arbitrary (e.g. a 9-byte
 * "127.0.0.1" IP string). Compute the ring offset from the 8-aligned node
 * base and round the whole header span up to sizeof(time_t); anything else
 * leaves the time_t stores/loads misaligned (UB; trapped by UBSan, would
 * fault on strict-alignment arches). sentinel_shm_create_node sizes the
 * allocation with the identical formula. */
static ngx_inline size_t
sentinel_events_offset(u_short key_len)
{
    return ngx_align(offsetof(ngx_sentinel_node_t, data) + key_len,
                     sizeof(time_t));
}

static ngx_inline time_t *
sentinel_node_events(ngx_sentinel_node_t *n)
{
    return (time_t *) ((u_char *) n + sentinel_events_offset(n->key_len));
}

/* Expire the oldest (LRU tail) entries in batches to keep the zone bounded. */
static void
sentinel_shm_expire(ngx_sentinel_zone_t *zone, time_t now, ngx_uint_t batch)
{
    ngx_queue_t          *tail;
    ngx_sentinel_node_t  *n;
    ngx_uint_t            i;

    for (i = 0; i < batch; i++) {
        if (ngx_queue_empty(&zone->sh->queue)) {
            break;
        }

        tail = ngx_queue_last(&zone->sh->queue);
        n = ngx_queue_data(tail, ngx_sentinel_node_t, queue);

        /* Keep entries that are still within their TTL (block or last_seen). */
        if (n->blocked_until > now) {
            break;
        }
        if (now - n->last_seen < zone->interval) {
            break;
        }

        ngx_queue_remove(&n->queue);
        ngx_rbtree_delete(&zone->sh->rbtree, &n->node);
        ngx_slab_free_locked(zone->shpool, n);
    }
}

/* Touch (move to LRU head). */
static ngx_inline void
sentinel_shm_touch(ngx_sentinel_zone_t *zone, ngx_sentinel_node_t *n)
{
    ngx_queue_remove(&n->queue);
    ngx_queue_insert_head(&zone->sh->queue, &n->queue);
}

/* Prune events outside the sliding window. */
static void
sentinel_shm_prune(ngx_sentinel_zone_t *zone, ngx_sentinel_node_t *n,
    time_t now)
{
    time_t     *events;
    ngx_uint_t  i, keep;
    time_t      cutoff;

    events = sentinel_node_events(n);
    cutoff = now - zone->interval;
    keep = 0;

    for (i = 0; i < n->event_count; i++) {
        time_t ts = events[(n->event_head + i) % zone->threshold];
        if (ts > cutoff) {
            events[keep] = ts;
            keep++;
        }
    }
    n->event_head  = 0;
    n->event_count = keep;
}

/* rbtree lookup by hash + key bytes. */
static ngx_sentinel_node_t *
sentinel_shm_lookup(ngx_sentinel_zone_t *zone, uint32_t hash, ngx_str_t *key)
{
    ngx_int_t             rc;
    ngx_rbtree_node_t    *node, *sentinel;
    ngx_sentinel_node_t  *n;

    node     = zone->sh->rbtree.root;
    sentinel = zone->sh->rbtree.sentinel;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }
        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash match — compare key bytes */
        n  = (ngx_sentinel_node_t *) node;
        rc = ngx_memn2cmp(key->data, n->data, key->len, (size_t) n->key_len);
        if (rc == 0) {
            return n;
        }
        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

/* Allocate a new node (slab). Returns NULL on zone-full. */
static ngx_sentinel_node_t *
sentinel_shm_create_node(ngx_sentinel_zone_t *zone, uint32_t hash,
    ngx_str_t *key, time_t now)
{
    size_t                size;
    ngx_sentinel_node_t  *n;

    /* 8-aligned header span (node + key bytes, padded so the event ring
     * starts on an 8-byte boundary) + threshold * sizeof(time_t) for the
     * ring. Mirrors sentinel_node_events()/sentinel_events_offset(); without
     * the padding the ring's time_t accesses are misaligned (UB). */
    size = sentinel_events_offset((u_short) key->len)
           + zone->threshold * sizeof(time_t);

    n = ngx_slab_calloc_locked(zone->shpool, size);
    if (n == NULL) {
        return NULL;
    }

    n->node.key    = hash;
    n->key_len     = (u_short) key->len;
    n->last_seen   = now;
    n->event_head  = 0;
    n->event_count = 0;
    n->blocked_until = 0;
    ngx_memcpy(n->data, key->data, key->len);

    ngx_rbtree_insert(&zone->sh->rbtree, &n->node);
    ngx_queue_insert_head(&zone->sh->queue, &n->queue);

    return n;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void
sentinel_shm_rbtree_insert(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_int_t             rc;
    ngx_rbtree_node_t   **p;
    ngx_sentinel_node_t  *n, *nt;

    for ( ;; ) {
        if (node->key < temp->key) {
            p = &temp->left;
        } else if (node->key > temp->key) {
            p = &temp->right;
        } else {
            n  = (ngx_sentinel_node_t *) node;
            nt = (ngx_sentinel_node_t *) temp;
            rc = ngx_memn2cmp(n->data, nt->data,
                              n->key_len, nt->key_len);
            p = (rc < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }
        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left   = sentinel;
    node->right  = sentinel;
    ngx_rbt_red(node);
}

ngx_int_t
sentinel_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                 len;
    ngx_sentinel_zone_t   *zone, *old;

    zone = shm_zone->data;
    old  = data;

    if (old != NULL) {
        /* Reload: reuse the existing shared context. */
        zone->sh     = old->sh;
        zone->shpool = old->shpool;
        return NGX_OK;
    }

    zone->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        zone->sh = zone->shpool->data;
        return NGX_OK;
    }

    zone->sh = ngx_slab_alloc(zone->shpool, sizeof(ngx_sentinel_shctx_t));
    if (zone->sh == NULL) {
        return NGX_ERROR;
    }

    zone->shpool->data = zone->sh;

    ngx_rbtree_init(&zone->sh->rbtree, &zone->sh->sentinel_rb,
                    sentinel_shm_rbtree_insert);
    ngx_queue_init(&zone->sh->queue);
    zone->sh->cs_generation = 0;  /* slab_alloc does not zero; mark-sweep tag */

    len = sizeof(" in sentinel zone \"\"") + zone->name.len;
    zone->shpool->log_ctx = ngx_slab_alloc(zone->shpool, len);
    if (zone->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(zone->shpool->log_ctx, " in sentinel zone \"%V\"%Z",
                &zone->name);

    return NGX_OK;
}

ngx_int_t
sentinel_shm_errrate_lookup(ngx_sentinel_zone_t *zone, ngx_str_t *key,
    time_t now, ngx_uint_t *count, time_t *blocked_until)
{
    uint32_t              hash;
    ngx_sentinel_node_t  *n;

    *count         = 0;
    *blocked_until = 0;

    if (zone == NULL || zone->sh == NULL || zone->shpool == NULL) {
        return NGX_ERROR;
    }

    hash = ngx_crc32_short(key->data, key->len);

    ngx_shmtx_lock(&zone->shpool->mutex);

    sentinel_shm_expire(zone, now, NGX_SENTINEL_EXPIRE_BATCH);

    n = sentinel_shm_lookup(zone, hash, key);

    if (n == NULL) {
        ngx_shmtx_unlock(&zone->shpool->mutex);
        return NGX_OK;
    }

    sentinel_shm_touch(zone, n);
    n->last_seen = now;

    if (n->blocked_until > now) {
        *count         = zone->threshold;
        *blocked_until = n->blocked_until;
        ngx_shmtx_unlock(&zone->shpool->mutex);
        return NGX_BUSY;
    }

    if (n->blocked_until != 0) {
        n->blocked_until  = 0;
        n->event_head     = 0;
        n->event_count    = 0;
    } else {
        sentinel_shm_prune(zone, n, now);
    }

    *count         = n->event_count;
    *blocked_until = 0;

    ngx_shmtx_unlock(&zone->shpool->mutex);
    return NGX_OK;
}

/* -------------------------------------------------------------------------
 * Phase 3 — CrowdSec ban table helpers
 *
 * CrowdSec nodes share ngx_sentinel_node_t but allocate with NO event ring
 * (the crowdsec zone has threshold==0). blocked_until = decision expiry;
 * cs_action / cs_generation carry the action tier and mark-sweep stamp.
 * ---------------------------------------------------------------------- */

/* Allocate a crowdsec node (slab) with no event ring. NULL on zone-full. */
static ngx_sentinel_node_t *
sentinel_shm_crowdsec_create(ngx_sentinel_zone_t *zone, uint32_t hash,
    ngx_str_t *key, time_t now)
{
    size_t                size;
    ngx_sentinel_node_t  *n;

    /* node + key bytes only (threshold==0 => zero-length event ring). */
    size = sizeof(ngx_sentinel_node_t) + key->len;

    n = ngx_slab_calloc_locked(zone->shpool, size);
    if (n == NULL) {
        return NULL;
    }

    n->node.key      = hash;
    n->key_len       = (u_short) key->len;
    n->last_seen     = now;
    n->event_head    = 0;
    n->event_count   = 0;
    n->blocked_until = 0;
    n->cs_action     = NGX_SENTINEL_CS_NONE;
    n->cs_generation = 0;
    n->redis_pulled  = 0;
    ngx_memcpy(n->data, key->data, key->len);

    ngx_rbtree_insert(&zone->sh->rbtree, &n->node);
    ngx_queue_insert_head(&zone->sh->queue, &n->queue);

    return n;
}

ngx_int_t
sentinel_shm_crowdsec_upsert(ngx_sentinel_zone_t *zone, ngx_str_t *key,
    time_t expiry, u_char action, ngx_uint_t generation, time_t now,
    u_char redis_pulled)
{
    uint32_t              hash;
    ngx_sentinel_node_t  *n;

    if (zone == NULL || zone->sh == NULL || zone->shpool == NULL) {
        return NGX_ERROR;
    }

    hash = ngx_crc32_short(key->data, key->len);

    n = sentinel_shm_lookup(zone, hash, key);
    if (n == NULL) {
        n = sentinel_shm_crowdsec_create(zone, hash, key, now);
        if (n == NULL) {
            return NGX_ERROR;   /* zone full — caller logs partial load */
        }
    } else {
        sentinel_shm_touch(zone, n);
    }

    n->blocked_until = expiry;
    n->cs_action     = action;
    n->cs_generation = generation;
    n->redis_pulled  = redis_pulled;
    n->last_seen     = now;

    return NGX_OK;
}

ngx_uint_t
sentinel_shm_crowdsec_sweep(ngx_sentinel_zone_t *zone, ngx_uint_t generation,
    ngx_uint_t batch)
{
    ngx_queue_t          *q, *prev;
    ngx_sentinel_node_t  *n;
    ngx_uint_t            deleted = 0;

    if (zone == NULL || zone->sh == NULL) {
        return 0;
    }

    q = ngx_queue_last(&zone->sh->queue);

    while (q != ngx_queue_sentinel(&zone->sh->queue) && deleted < batch) {
        prev = ngx_queue_prev(q);
        n = ngx_queue_data(q, ngx_sentinel_node_t, queue);

        if (n->cs_generation != generation) {
            ngx_queue_remove(&n->queue);
            ngx_rbtree_delete(&zone->sh->rbtree, &n->node);
            ngx_slab_free_locked(zone->shpool, n);
            deleted++;
        }

        q = prev;
    }

    return deleted;
}

ngx_int_t
sentinel_shm_crowdsec_lookup(ngx_sentinel_zone_t *zone, ngx_str_t *key,
    time_t now, u_char *action)
{
    uint32_t              hash;
    ngx_sentinel_node_t  *n;
    ngx_int_t             rc;

    *action = NGX_SENTINEL_CS_NONE;

    if (zone == NULL || zone->sh == NULL || zone->shpool == NULL) {
        return NGX_ERROR;
    }

    hash = ngx_crc32_short(key->data, key->len);

    ngx_shmtx_lock(&zone->shpool->mutex);

    /* TTL/LRU backstop: ages out abandoned entries (interval=stale_after). */
    sentinel_shm_expire(zone, now, NGX_SENTINEL_EXPIRE_BATCH);

    n = sentinel_shm_lookup(zone, hash, key);

    if (n == NULL || n->blocked_until <= now) {
        rc = NGX_OK;
        if (n != NULL) {
            sentinel_shm_touch(zone, n);
            n->last_seen = now;
        }
        ngx_shmtx_unlock(&zone->shpool->mutex);
        return rc;
    }

    /* Copy action out while locked; the node may be freed after unlock. */
    *action = n->cs_action;
    sentinel_shm_touch(zone, n);
    n->last_seen = now;

    ngx_shmtx_unlock(&zone->shpool->mutex);
    return NGX_BUSY;
}

/*
 * sentinel_shm_errrate_record — record an error event for `key`.
 * Used by sentinel_errrate.c after a response has been observed.
 * Returns NGX_OK (tracking), NGX_BUSY (now blocked), NGX_ERROR (zone full).
 */
ngx_int_t
sentinel_shm_errrate_record(ngx_sentinel_zone_t *zone, ngx_str_t *key,
    time_t now, ngx_uint_t *count, time_t *blocked_until)
{
    uint32_t              hash;
    ngx_uint_t            idx;
    time_t               *events;
    ngx_sentinel_node_t  *n;

    *count         = 0;
    *blocked_until = 0;

    if (zone == NULL || zone->sh == NULL || zone->shpool == NULL) {
        return NGX_ERROR;
    }

    hash = ngx_crc32_short(key->data, key->len);

    ngx_shmtx_lock(&zone->shpool->mutex);

    sentinel_shm_expire(zone, now, NGX_SENTINEL_EXPIRE_BATCH);

    n = sentinel_shm_lookup(zone, hash, key);
    if (n == NULL) {
        n = sentinel_shm_create_node(zone, hash, key, now);
        if (n == NULL) {
            ngx_shmtx_unlock(&zone->shpool->mutex);
            return NGX_ERROR;
        }
    } else {
        sentinel_shm_touch(zone, n);
        n->last_seen = now;
    }

    if (n->blocked_until > now) {
        *count         = zone->threshold;
        *blocked_until = n->blocked_until;
        ngx_shmtx_unlock(&zone->shpool->mutex);
        return NGX_BUSY;
    }

    if (n->blocked_until != 0) {
        n->blocked_until  = 0;
        n->event_head     = 0;
        n->event_count    = 0;
    }

    sentinel_shm_prune(zone, n, now);

    events = sentinel_node_events(n);
    idx    = (n->event_head + n->event_count) % zone->threshold;
    events[idx] = now;
    n->event_count++;

    if (n->event_count >= zone->threshold) {
        n->blocked_until  = now + zone->block;
        n->event_head     = 0;
        n->event_count    = 0;
    }

    *count         = (n->blocked_until > now) ? zone->threshold
                                              : n->event_count;
    *blocked_until = n->blocked_until;

    ngx_shmtx_unlock(&zone->shpool->mutex);
    return (n->blocked_until > now) ? NGX_BUSY : NGX_OK;
}

/*
 * sentinel_shm_softban_set — persist a self-ban for `key` in the errrate zone.
 *
 * On a BLOCK verdict (enforce mode) with sentinel_block_ttl > 0, the preaccess
 * handler calls this to write blocked_until = now + ttl.  A subsequent request
 * from the same identity is short-circuited by errrate_lookup (returns NGX_BUSY
 * while blocked_until > now), so the block self-persists for the TTL with NO
 * re-evaluation of the original signals.
 *
 * Reuses the same lock + node-alloc + eviction path as errrate_record (the
 * node carries an event ring it never uses for soft-bans — harmless, keeps the
 * slab sizing identical to the errrate node so a key may be either at any time).
 * Returns NGX_OK on success, NGX_ERROR on zone-full / bad zone (caller logs +
 * fails open).
 */
ngx_int_t
sentinel_shm_softban_set(ngx_sentinel_zone_t *zone, ngx_str_t *key,
    time_t now, time_t ttl)
{
    uint32_t              hash;
    ngx_sentinel_node_t  *n;

    if (zone == NULL || zone->sh == NULL || zone->shpool == NULL || ttl <= 0) {
        return NGX_ERROR;
    }

    hash = ngx_crc32_short(key->data, key->len);

    ngx_shmtx_lock(&zone->shpool->mutex);

    sentinel_shm_expire(zone, now, NGX_SENTINEL_EXPIRE_BATCH);

    n = sentinel_shm_lookup(zone, hash, key);
    if (n == NULL) {
        n = sentinel_shm_create_node(zone, hash, key, now);
        if (n == NULL) {
            ngx_shmtx_unlock(&zone->shpool->mutex);
            return NGX_ERROR;   /* zone full */
        }
    } else {
        sentinel_shm_touch(zone, n);
    }

    n->last_seen      = now;
    n->blocked_until  = now + ttl;
    /* Drop any in-flight burst window — the ban supersedes it. */
    n->event_head     = 0;
    n->event_count    = 0;

    ngx_shmtx_unlock(&zone->shpool->mutex);
    return NGX_OK;
}

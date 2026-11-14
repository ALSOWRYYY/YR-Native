/* dispatch_index.h - VA-indexed bucket lookup over recomp_dispatch_table.
 *
 * Included only by native32.c (and its offline equivalence test). The binary
 * search is kept verbatim as the fallback and as the reference answer.
 *
 * index->bucket[k] = first table index whose address >= lo + (k << SHIFT).
 * A lookup is: one subtraction, one shift, two bucket loads, and an exact-match
 * scan of the (usually 0-2) entries inside a 128-byte VA window.
 *
 * The generated table is immutable for process lifetime. Publish one owned,
 * immutable allocation atomically; concurrent builders discard their losing
 * allocation. Readers never observe metadata from an unfinished build. The
 * published allocation lives until process exit (there is no runtime reset).
 * Before publication, or for an unindexable table, retain the original binary
 * search. This preserves its result even for malformed input; it does not make
 * an unsorted table valid.
 */
#ifndef PCRECOMP_DISPATCH_INDEX_H
#define PCRECOMP_DISPATCH_INDEX_H

#if !defined(_MSC_VER) || !defined(_M_IX86)
#error "native32 dispatch publication requires MSVC x86"
#endif

#define DISPATCH_BUCKET_SHIFT 7u
#define DISPATCH_INDEX_MAX_BYTES (4u * 1024u * 1024u)

typedef struct {
    uint32_t lo, nbuckets;
    uint32_t bucket[1]; /* nbuckets + 1 offsets follow, including the sentinel */
} dispatch_index_t;
static PVOID volatile g_dispatch_index;

static const dispatch_index_t* dispatch_index_read(void) {
    /* x86's aligned pointer load is atomic and loads are acquire-ordered.
     * SDK ReadPointerAcquire is a volatile load on this target. The explicit
     * compiler barrier also covers /volatile:iso; no locked RMW in readers. */
    const dispatch_index_t* index = (const dispatch_index_t*)ReadPointerAcquire(&g_dispatch_index);
    _ReadWriteBarrier();
    return index;
}

static recomp_func_t dispatch_find_bsearch(uint32_t va) {
    uint32_t lo = 0, hi = recomp_dispatch_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2, m = recomp_dispatch_table[mid].address;
        if (m == va) return recomp_dispatch_table[mid].func;
        if (m < va) lo = mid + 1; else hi = mid;
    }
    return NULL;
}

/* Returns 1 if the index was built, 0 if the binary search stays in use. */
static int dispatch_index_build(void) {
    uint32_t n = recomp_dispatch_count, i, k, nb, lo, hi;
    dispatch_index_t* index;
    size_t bytes;
    if (dispatch_index_read()) return 1;
    if (n == 0) return 0;
    for (i = 1; i < n; i++)
        if (recomp_dispatch_table[i - 1].address >= recomp_dispatch_table[i].address) return 0;
    lo = recomp_dispatch_table[0].address;
    hi = recomp_dispatch_table[n - 1].address;
    nb = ((hi - lo) >> DISPATCH_BUCKET_SHIFT) + 1;          /* buckets that can hold an entry */
    /* A sparse 32-bit VA range must not allocate 128 MiB just to find two
     * entries. Bound before arithmetic/allocation; all rejected cases keep
     * the exact old lookup contract. */
    if (nb > (DISPATCH_INDEX_MAX_BYTES - sizeof *index) / sizeof(uint32_t)) return 0;
    bytes = sizeof *index + (size_t)nb * sizeof(uint32_t);
    index = (dispatch_index_t*)HeapAlloc(GetProcessHeap(), 0, bytes);
    if (!index) return 0;
    index->lo = lo;
    index->nbuckets = nb;
    for (i = 0, k = 0; k < nb; k++) {
        uint32_t start = lo + (k << DISPATCH_BUCKET_SHIFT);
        while (i < n && recomp_dispatch_table[i].address < start) i++;
        index->bucket[k] = i;
    }
    index->bucket[nb] = n;
    if (InterlockedCompareExchangePointer(&g_dispatch_index, index, NULL))
        HeapFree(GetProcessHeap(), 0, index);
    return 1;
}

static recomp_func_t dispatch_find(uint32_t va) {
    const dispatch_index_t* index = dispatch_index_read();
    const uint32_t* b;
    uint32_t k, i, e;
    if (!index) return dispatch_find_bsearch(va);
    if (va < index->lo) return NULL;
    k = (va - index->lo) >> DISPATCH_BUCKET_SHIFT;
    if (k >= index->nbuckets) return NULL;
    b = index->bucket;
    for (i = b[k], e = b[k + 1]; i < e; i++)
        if (recomp_dispatch_table[i].address == va) return recomp_dispatch_table[i].func;
    return NULL;
}

#endif

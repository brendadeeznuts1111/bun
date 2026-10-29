#pragma once

// Included after lazy_sqlite3.h so all allocation and VFS calls use the same
// SQLite library as the connection. Native VFS objects remain alive after
// unregistering; only their public names are removed from SQLite's registry.
#include <cstdlib>
#include <cstring>
#include <mutex>

extern "C" bool Bun__Process__filePathsRestricted();
extern "C" bool Bun__Process__permissionHas(const uint8_t*, size_t, const uint8_t*, size_t);
extern "C" bool Bun__Process__fileEntryAllowed(const uint8_t*, size_t, const uint8_t*, size_t);

namespace Bun::SQLitePermissions {

inline bool allowed(bool write, const char* path, bool entry = false)
{
    const char* scope = write ? "fs.write" : "fs.read";
    auto check = entry ? Bun__Process__fileEntryAllowed : Bun__Process__permissionHas;
    return check(reinterpret_cast<const uint8_t*>(scope), strlen(scope),
        reinterpret_cast<const uint8_t*>(path), path ? strlen(path) : 0);
}

inline bool writable(const char* path)
{
    return allowed(true, path, true) && allowed(true, path);
}

struct File {
    sqlite3_file file;
    sqlite3_file* underlying;
    char* path;
    char* sharedMemoryPath;
};

inline File* file(sqlite3_file* value) { return reinterpret_cast<File*>(value); }
inline sqlite3_vfs* underlying(sqlite3_vfs* vfs) { return static_cast<sqlite3_vfs*>(vfs->pAppData); }
inline bool readable(File* f) { return allowed(false, f->path); }
inline bool writable(File* f) { return writable(f->path); }
inline bool sharedMemoryAllowed(File* f)
{
    // The native VFS opens -shm internally, without another VFS xOpen call.
    return readable(f) && writable(f) && allowed(false, f->sharedMemoryPath) && writable(f->sharedMemoryPath);
}

inline int close(sqlite3_file* value)
{
    auto* f = file(value);
    int rc = f->underlying->pMethods->xClose(f->underlying);
    sqlite3_free(f->underlying);
    free(f->path);
    free(f->sharedMemoryPath);
    f->file.pMethods = nullptr;
    return rc;
}
inline int read(sqlite3_file* value, void* buffer, int amount, sqlite3_int64 offset)
{
    auto* f = file(value);
    if (!readable(f)) {
        memset(buffer, 0, amount);
        return SQLITE_IOERR_AUTH;
    }
    return f->underlying->pMethods->xRead(f->underlying, buffer, amount, offset);
}
inline int write(sqlite3_file* value, const void* buffer, int amount, sqlite3_int64 offset)
{
    auto* f = file(value);
    return writable(f) ? f->underlying->pMethods->xWrite(f->underlying, buffer, amount, offset) : SQLITE_IOERR_AUTH;
}
inline int truncate(sqlite3_file* value, sqlite3_int64 size)
{
    auto* f = file(value);
    return writable(f) ? f->underlying->pMethods->xTruncate(f->underlying, size) : SQLITE_IOERR_AUTH;
}
inline int sync(sqlite3_file* value, int flags)
{
    auto* f = file(value);
    return writable(f) ? f->underlying->pMethods->xSync(f->underlying, flags) : SQLITE_IOERR_AUTH;
}
inline int size(sqlite3_file* value, sqlite3_int64* result)
{
    auto* f = file(value);
    *result = 0;
    return readable(f) ? f->underlying->pMethods->xFileSize(f->underlying, result) : SQLITE_IOERR_AUTH;
}
inline int lock(sqlite3_file* value, int level)
{
    auto* f = file(value);
    if (!readable(f) || (level > SQLITE_LOCK_SHARED && !writable(f)))
        return SQLITE_IOERR_AUTH;
    return f->underlying->pMethods->xLock(f->underlying, level);
}
inline int unlock(sqlite3_file* value, int level)
{
    auto* f = file(value);
    return f->underlying->pMethods->xUnlock(f->underlying, level);
}
inline int reservedLock(sqlite3_file* value, int* result)
{
    auto* f = file(value);
    *result = 0;
    return readable(f) ? f->underlying->pMethods->xCheckReservedLock(f->underlying, result) : SQLITE_IOERR_AUTH;
}
inline int control(sqlite3_file* value, int operation, void* argument)
{
    auto* f = file(value);
    // Do not expose native file pointers, alternate VFSes, mmap, or unreviewed
    // pragma hooks. SQLite falls back to its own implementation on NOTFOUND.
    switch (operation) {
    case SQLITE_FCNTL_PERSIST_WAL:
        // SQLite queries this flag at close to decide whether to delete WAL
        // sidecars. Preserve the native default for read-only reopening.
        if (!argument || !readable(f) || (*static_cast<int*>(argument) >= 0 && !writable(f)))
            return SQLITE_IOERR_AUTH;
        break;
    case SQLITE_FCNTL_SIZE_HINT:
    case SQLITE_FCNTL_CHUNK_SIZE:
    case SQLITE_FCNTL_SYNC:
        if (!writable(f))
            return SQLITE_IOERR_AUTH;
        break;
    case SQLITE_FCNTL_LOCKSTATE:
    case SQLITE_FCNTL_HAS_MOVED:
        if (!readable(f))
            return SQLITE_IOERR_AUTH;
        break;
    default:
        return SQLITE_NOTFOUND;
    }
    int rc = f->underlying->pMethods->xFileControl(f->underlying, operation, argument);
    return rc;
}
inline int sectorSize(sqlite3_file* value)
{
    auto* f = file(value);
    return readable(f) ? f->underlying->pMethods->xSectorSize(f->underlying) : 512;
}
inline int characteristics(sqlite3_file* value)
{
    auto* f = file(value);
    return readable(f) ? f->underlying->pMethods->xDeviceCharacteristics(f->underlying) : 0;
}
inline int shmMap(sqlite3_file* value, int page, int size, int extend, void volatile** output)
{
    auto* f = file(value);
    *output = nullptr;
    if (!sharedMemoryAllowed(f)) {
        return SQLITE_IOERR_AUTH;
    }
    // Short-name builds derive a different -shm pathname internally.
    if (sqlite3_compileoption_used("ENABLE_8_3_NAMES"))
        return SQLITE_IOERR_SHMMAP;
    if (f->underlying->pMethods->iVersion < 2 || !f->underlying->pMethods->xShmMap)
        return SQLITE_IOERR_SHMMAP;
    int rc = f->underlying->pMethods->xShmMap(f->underlying, page, size, extend, output);
    return rc;
}
inline int shmLock(sqlite3_file* value, int offset, int count, int flags)
{
    auto* f = file(value);
    if (!(flags & SQLITE_SHM_UNLOCK) && !sharedMemoryAllowed(f))
        return SQLITE_IOERR_AUTH;
    if (f->underlying->pMethods->iVersion < 2 || !f->underlying->pMethods->xShmLock)
        return SQLITE_IOERR_SHMLOCK;
    return f->underlying->pMethods->xShmLock(f->underlying, offset, count, flags);
}
inline void shmBarrier(sqlite3_file* value)
{
    auto* f = file(value);
    if (f->underlying->pMethods->iVersion >= 2 && f->underlying->pMethods->xShmBarrier)
        f->underlying->pMethods->xShmBarrier(f->underlying);
}
inline int shmUnmap(sqlite3_file* value, int remove)
{
    auto* f = file(value);
    if (f->underlying->pMethods->iVersion < 2 || !f->underlying->pMethods->xShmUnmap)
        return SQLITE_OK;
    // Always permit relinquishing a mapping, but never an unauthorized unlink.
    bool denied = remove && !allowed(true, f->sharedMemoryPath, true);
    int rc = f->underlying->pMethods->xShmUnmap(f->underlying, denied ? 0 : remove);
    return denied ? SQLITE_IOERR_AUTH : rc;
}
inline int fetch(sqlite3_file*, sqlite3_int64, int, void** output)
{
    *output = nullptr; // SQLite falls back to the permission-checked xRead.
    return SQLITE_OK;
}
inline int unfetch(sqlite3_file*, sqlite3_int64, void*) { return SQLITE_OK; }

inline const sqlite3_io_methods methods = { 3, close, read, write, truncate, sync, size,
    lock, unlock, reservedLock, control, sectorSize, characteristics,
    shmMap, shmLock, shmBarrier, shmUnmap, fetch, unfetch };

inline int open(sqlite3_vfs* vfs, const char* name, sqlite3_file* output, int flags, int* outputFlags)
{
    auto* f = file(output);
    memset(f, 0, sizeof(*f));
    if (!allowed(false, name) || ((flags & (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_DELETEONCLOSE)) && !writable(name))) {
        return SQLITE_CANTOPEN;
    }
    // A NULL name asks the native VFS to choose a temporary pathname. Partial
    // grants cannot authorize that unknown destination. Memory DBs do not open
    // a native file and remain usable.
    if (!name)
        return SQLITE_CANTOPEN;
    auto* base = underlying(vfs);
    f->underlying = static_cast<sqlite3_file*>(sqlite3_malloc64(base->szOsFile));
    size_t length = strlen(name);
    f->path = static_cast<char*>(malloc(length + 1));
    f->sharedMemoryPath = static_cast<char*>(malloc(length + 5));
    if (!f->underlying || !f->path || !f->sharedMemoryPath) {
        sqlite3_free(f->underlying);
        free(f->path);
        free(f->sharedMemoryPath);
        return SQLITE_NOMEM;
    }
    memcpy(f->path, name, length + 1);
    memcpy(f->sharedMemoryPath, name, length);
    memcpy(f->sharedMemoryPath + length, "-shm", 5);
    memset(f->underlying, 0, base->szOsFile);
    // Preserve SQLite's original filename and its hidden URI parameters.
    int rc = base->xOpen(base, name, f->underlying, flags, outputFlags);
    if (rc != SQLITE_OK) {
        if (f->underlying->pMethods)
            f->underlying->pMethods->xClose(f->underlying);
        sqlite3_free(f->underlying);
        free(f->path);
        free(f->sharedMemoryPath);
        return rc;
    }
    f->file.pMethods = &methods;
    return SQLITE_OK;
}
inline int remove(sqlite3_vfs* vfs, const char* name, int syncDirectory)
{
    return allowed(true, name, true) ? underlying(vfs)->xDelete(underlying(vfs), name, syncDirectory) : SQLITE_IOERR_AUTH;
}
inline int access(sqlite3_vfs* vfs, const char* name, int flags, int* output)
{
    *output = 0;
    if (!allowed(false, name) || (flags == SQLITE_ACCESS_READWRITE && !writable(name)))
        return SQLITE_IOERR_AUTH;
    int rc = underlying(vfs)->xAccess(underlying(vfs), name, flags, output);
    return rc;
}
inline int fullPath(sqlite3_vfs* vfs, const char* name, int size, char* output)
{
    if (!allowed(false, name)) {
        return SQLITE_CANTOPEN;
    }
    return underlying(vfs)->xFullPathname(underlying(vfs), name, size, output);
}
inline void* dlOpen(sqlite3_vfs* vfs, const char* name)
{
    return Bun__Process__nativeCodeAllowed() ? underlying(vfs)->xDlOpen(underlying(vfs), name) : nullptr;
}
inline void dlError(sqlite3_vfs* vfs, int size, char* output)
{
    if (Bun__Process__nativeCodeAllowed())
        underlying(vfs)->xDlError(underlying(vfs), size, output);
    else if (size > 0)
        output[0] = 0;
}
inline void (*dlSym(sqlite3_vfs* vfs, void* library, const char* name))(void)
{
    return Bun__Process__nativeCodeAllowed() ? underlying(vfs)->xDlSym(underlying(vfs), library, name) : nullptr;
}
inline void dlClose(sqlite3_vfs* vfs, void* library) { underlying(vfs)->xDlClose(underlying(vfs), library); }
inline int randomness(sqlite3_vfs* vfs, int size, char* output) { return underlying(vfs)->xRandomness(underlying(vfs), size, output); }
inline int sleep(sqlite3_vfs* vfs, int delay) { return underlying(vfs)->xSleep(underlying(vfs), delay); }
inline int currentTime(sqlite3_vfs* vfs, double* output) { return underlying(vfs)->xCurrentTime(underlying(vfs), output); }
inline int lastError(sqlite3_vfs* vfs, int size, char* output)
{
    return underlying(vfs)->xGetLastError ? underlying(vfs)->xGetLastError(underlying(vfs), size, output) : 0;
}
inline int currentTimeInt64(sqlite3_vfs* vfs, sqlite3_int64* output)
{
    auto* base = underlying(vfs);
    if (base->iVersion >= 2 && base->xCurrentTimeInt64)
        return base->xCurrentTimeInt64(base, output);
    double time;
    int rc = base->xCurrentTime(base, &time);
    if (rc == SQLITE_OK)
        *output = static_cast<sqlite3_int64>(time * 86400000.0);
    return rc;
}

inline int initialize()
{
    if (!Bun__Process__filePathsRestricted())
        return SQLITE_OK;
    static std::once_flag once;
    static int result = SQLITE_ERROR;
    static sqlite3_vfs wrapper;
    std::call_once(once, [] {
#if LAZY_LOAD_SQLITE
        if (!sqlite3_vfs_find || !sqlite3_vfs_register || !sqlite3_vfs_unregister)
            return;
#endif
        // macOS' auto-lock VFS may create proxy/conch files outside VFS xOpen.
        // Prefer its ordinary POSIX-lock variant, when supplied by that build.
        sqlite3_vfs* base = sqlite3_vfs_find("unix-posix");
        if (!base)
            base = sqlite3_vfs_find(nullptr);
        if (!base)
            return;
        wrapper = { 2, sizeof(File), base->mxPathname, nullptr, "bun-permissions", base,
            open, remove, access, fullPath, dlOpen, dlError, dlSym, dlClose,
            randomness, sleep, currentTime, lastError, currentTimeInt64, nullptr, nullptr, nullptr };
        // URI vfs= parameters can select non-default VFSes even during ATTACH.
        // Remove those names before exposing a connection to JavaScript.
        auto* registered = sqlite3_vfs_find(nullptr);
        while (registered) {
            auto* next = registered->pNext;
            // sqlite3_deserialize reopens through this built-in heap-only VFS.
            // It does not issue filesystem opens, including for URI filenames.
            if (strcmp(registered->zName, "memdb") != 0) {
                result = sqlite3_vfs_unregister(registered);
                if (result != SQLITE_OK)
                    return;
            }
            registered = next;
        }
        result = sqlite3_vfs_register(&wrapper, 1);
    });
    return result;
}

} // namespace Bun::SQLitePermissions

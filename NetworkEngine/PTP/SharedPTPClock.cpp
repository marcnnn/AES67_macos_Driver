//
// SharedPTPClock.cpp
// AES67 macOS Driver
//

#include "SharedPTPClock.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include <atomic>
#include <cstring>

namespace AES67 {

namespace {

uint64_t monotonicNs() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL +
           static_cast<uint64_t>(ts.tv_nsec);
}

/// A sample older than this is not worth extrapolating from: the agent has
/// probably stopped, and a stale rate error would drift without bound.
constexpr uint64_t kMaxSampleAgeNs = 5000000000ULL;  // 5 s

std::atomic<uint32_t>* seqOf(SharedPTPClockData* d) {
    return reinterpret_cast<std::atomic<uint32_t>*>(&d->sequence);
}
const std::atomic<uint32_t>* seqOf(const SharedPTPClockData* d) {
    return reinterpret_cast<const std::atomic<uint32_t>*>(&d->sequence);
}

} // namespace

// ============================================================================
// Writer
// ============================================================================

SharedPTPClockWriter::SharedPTPClockWriter() = default;
SharedPTPClockWriter::~SharedPTPClockWriter() { close(); }

bool SharedPTPClockWriter::open(const std::string& path) {
    close();

    fd_ = ::open(path.c_str(), O_RDWR | O_CREAT, 0666);
    if (fd_ < 0) {
        return false;
    }

    // The driver runs as a different user, so the mapping has to be readable
    // by it. open()'s mode is filtered by umask, so set it explicitly.
    ::fchmod(fd_, 0666);

    if (::ftruncate(fd_, sizeof(SharedPTPClockData)) != 0) {
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    void* mapped = ::mmap(nullptr, sizeof(SharedPTPClockData),
                          PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
    if (mapped == MAP_FAILED) {
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    data_ = static_cast<SharedPTPClockData*>(mapped);
    data_->magic = SharedPTPClockData::kMagic;
    data_->version = SharedPTPClockData::kVersion;
    data_->locked = 0;
    data_->masterTimeNs = 0;
    data_->localMonotonicNs = 0;
    data_->frequencyPpb = 0.0;
    data_->updateCount = 0;
    seqOf(data_)->store(0, std::memory_order_release);
    return true;
}

void SharedPTPClockWriter::close() {
    if (data_) {
        // Park the sequence on an odd value so a reader treats whatever is
        // left behind as a write in progress rather than a valid sample.
        seqOf(data_)->store(1, std::memory_order_release);
        ::munmap(data_, sizeof(SharedPTPClockData));
        data_ = nullptr;
    }
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

void SharedPTPClockWriter::publish(uint64_t masterTimeNs, double frequencyPpb,
                                   bool locked) {
    if (!data_) {
        return;
    }

    auto* seq = seqOf(data_);
    const uint32_t start = seq->load(std::memory_order_relaxed);

    // Odd while writing.
    seq->store(start + 1, std::memory_order_release);
    std::atomic_thread_fence(std::memory_order_release);

    data_->masterTimeNs = masterTimeNs;
    data_->localMonotonicNs = monotonicNs();
    data_->frequencyPpb = frequencyPpb;
    data_->locked = locked ? 1u : 0u;
    data_->updateCount++;

    std::atomic_thread_fence(std::memory_order_release);
    seq->store(start + 2, std::memory_order_release);
}

// ============================================================================
// Reader
// ============================================================================

SharedPTPClockReader::SharedPTPClockReader() = default;
SharedPTPClockReader::~SharedPTPClockReader() { close(); }

bool SharedPTPClockReader::open(const std::string& path) {
    close();

    fd_ = ::open(path.c_str(), O_RDONLY);
    if (fd_ < 0) {
        return false;
    }

    struct stat st {};
    if (::fstat(fd_, &st) != 0 ||
        static_cast<size_t>(st.st_size) < sizeof(SharedPTPClockData)) {
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    void* mapped = ::mmap(nullptr, sizeof(SharedPTPClockData),
                          PROT_READ, MAP_SHARED, fd_, 0);
    if (mapped == MAP_FAILED) {
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    const auto* d = static_cast<const SharedPTPClockData*>(mapped);
    if (d->magic != SharedPTPClockData::kMagic ||
        d->version != SharedPTPClockData::kVersion) {
        ::munmap(mapped, sizeof(SharedPTPClockData));
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    data_ = d;
    return true;
}

void SharedPTPClockReader::close() {
    if (data_) {
        ::munmap(const_cast<SharedPTPClockData*>(data_), sizeof(SharedPTPClockData));
        data_ = nullptr;
    }
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

bool SharedPTPClockReader::isLocked() const {
    return data_ != nullptr && data_->locked != 0;
}

uint64_t SharedPTPClockReader::getMasterTimeNs() const {
    if (!data_) {
        return 0;
    }

    const auto* seq = seqOf(data_);

    // Sequence lock: retry while a write is in progress or one lands mid-read.
    for (int attempt = 0; attempt < 4; ++attempt) {
        const uint32_t before = seq->load(std::memory_order_acquire);
        if (before & 1u) {
            continue;  // writer active
        }

        const uint64_t master = data_->masterTimeNs;
        const uint64_t sampledAt = data_->localMonotonicNs;
        const double ppb = data_->frequencyPpb;
        const uint32_t locked = data_->locked;

        std::atomic_thread_fence(std::memory_order_acquire);
        if (seq->load(std::memory_order_acquire) != before) {
            continue;  // torn read
        }

        if (!locked || master == 0 || sampledAt == 0) {
            return 0;
        }

        const uint64_t now = monotonicNs();
        if (now < sampledAt) {
            return master;
        }

        const uint64_t elapsed = now - sampledAt;
        if (elapsed > kMaxSampleAgeNs) {
            return 0;  // agent has gone away; better to report nothing
        }

        // Project forward, correcting for the local clock's rate error against
        // the master. ppb is nanoseconds per second, so scale by elapsed
        // seconds; without this the estimate drifts at the crystal difference.
        const double correction =
            (static_cast<double>(elapsed) / 1e9) * ppb;
        return master + elapsed - static_cast<int64_t>(correction);
    }

    return 0;
}

} // namespace AES67

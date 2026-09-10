//
// SharedPTPClock.h
// AES67 macOS Driver
// Grandmaster time published by an external agent, read by the driver
//
// The driver, hosted inside coreaudiod, does not manage to run a PTP slave of
// its own. A small user-level agent runs one instead and publishes the result
// here; the driver reads it and uses it as its media clock. Nothing in this
// path needs elevated privileges.
//
// The transport is a fixed-size shared mapping. Writers publish with a
// sequence lock so a reader never observes a half-written sample, and readers
// take no locks at all -- important because this is read from the transmit
// path.
//

#pragma once

#include <cstdint>
#include <string>

namespace AES67 {

/// Layout of the shared mapping. Append-only: never reorder or resize existing
/// fields, or an agent and a driver from different builds will disagree.
struct SharedPTPClockData {
    static constexpr uint32_t kMagic   = 0x41455337;  // "AES7"
    static constexpr uint32_t kVersion = 1;

    uint32_t magic;
    uint32_t version;

    /// Incremented before and after each update. Odd means a write is in
    /// progress; a reader that sees the same even value either side of a read
    /// knows the sample was consistent.
    uint32_t sequence;
    uint32_t locked;          // non-zero once the slave has locked

    uint64_t masterTimeNs;    // grandmaster time at the instant below
    uint64_t localMonotonicNs;// CLOCK_MONOTONIC when masterTimeNs was sampled
    double   frequencyPpb;    // local clock rate error against the master
    uint64_t updateCount;     // for diagnostics
};

/// Default location. /tmp is reachable from the coreaudiod sandbox, which is
/// why the driver's debug log lives there too.
constexpr const char* kSharedPTPClockPath = "/tmp/aes67_ptp_clock";

//
// Writer -- used by the agent.
//
class SharedPTPClockWriter {
public:
    SharedPTPClockWriter();
    ~SharedPTPClockWriter();

    SharedPTPClockWriter(const SharedPTPClockWriter&) = delete;
    SharedPTPClockWriter& operator=(const SharedPTPClockWriter&) = delete;

    bool open(const std::string& path = kSharedPTPClockPath);
    void close();
    bool isOpen() const { return data_ != nullptr; }

    /// Publish a sample. masterTimeNs is on the grandmaster's timescale.
    void publish(uint64_t masterTimeNs, double frequencyPpb, bool locked);

private:
    int fd_{-1};
    SharedPTPClockData* data_{nullptr};
};

//
// Reader -- used by the driver.
//
class SharedPTPClockReader {
public:
    SharedPTPClockReader();
    ~SharedPTPClockReader();

    SharedPTPClockReader(const SharedPTPClockReader&) = delete;
    SharedPTPClockReader& operator=(const SharedPTPClockReader&) = delete;

    /// Map the clock. Fails when no agent has created it yet; callers should
    /// be prepared to retry, since the agent may start after the driver.
    bool open(const std::string& path = kSharedPTPClockPath);
    void close();
    bool isOpen() const { return data_ != nullptr; }

    /// Current grandmaster time in nanoseconds, or 0 when unavailable: no
    /// agent, not locked, or the last sample is too old to extrapolate from.
    ///
    /// The published sample is a point measurement, so project it forward from
    /// its own monotonic timestamp using the measured rate error -- the local
    /// clock ticks at a slightly different rate to the master, which is
    /// precisely what the sender must not accumulate.
    uint64_t getMasterTimeNs() const;

    bool isLocked() const;

private:
    int fd_{-1};
    const SharedPTPClockData* data_{nullptr};
};

} // namespace AES67

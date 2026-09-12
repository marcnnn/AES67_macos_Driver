#include "AudioThreadPriority.h"
#include "DebugLog.h"
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/thread_policy.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/resource.h>
#include <errno.h>
#include <cstring>
#include <cstdio>
#include <mach/mach_time.h>
#include <algorithm>
#include <atomic>

namespace AES67 {

bool AudioThreadPriority::configureForRealTime() {
    return configureThreadForRealTime(pthread_self());
}

bool AudioThreadPriority::configureForRealTimePeriodic(uint64_t periodNs,
                                                       uint64_t computationNs) {
    // Leave Darwin background before asking for anything else.
    //
    // A background-classified thread has its timer deadlines coalesced against
    // kern.timer_coalesce_bg_ns_max, which is 100ms, and the classification is
    // what the kernel consults -- not the latency tier requested further down,
    // whose own envelope (kern.timer_coalesce_tier0_ns_max) is 1ms. That gap is
    // the whole symptom: a 1ms send cadence leaves the wire as bursts of a
    // dozen packets with stalls of 15-37ms between them, the average rate
    // staying exactly right because the loop catches up. Deadline scheduling
    // and a latency-critical process activity were both tried first and
    // neither moved it, because neither changes this classification.
    //
    // Clearing it at process level as well as thread level is deliberate: the
    // transmit thread is created from whichever thread configured the stream,
    // and inherits the process default.
    const int threadBgBefore  = getpriority(PRIO_DARWIN_THREAD, 0);
    const int processBgBefore = getpriority(PRIO_DARWIN_PROCESS, 0);
    setpriority(PRIO_DARWIN_THREAD, 0, 0);
    setpriority(PRIO_DARWIN_PROCESS, 0, 0);
    AES67_LOGF("AudioThreadPriority: darwin background thread %d->%d process %d->%d",
               threadBgBefore, getpriority(PRIO_DARWIN_THREAD, 0),
               processBgBefore, getpriority(PRIO_DARWIN_PROCESS, 0));

    // Start from the existing configuration so the thread is also taken out of
    // the timeshare class; the time-constraint policy below is what actually
    // gets it scheduled on a deadline.
    configureForRealTime();

    mach_timebase_info_data_t timebase{};
    if (mach_timebase_info(&timebase) != KERN_SUCCESS || timebase.numer == 0) {
        return false;
    }

    // Policy values are in mach absolute time units, not nanoseconds.
    const double ticksPerNs = static_cast<double>(timebase.denom) /
                              static_cast<double>(timebase.numer);

    // Never claim more computation than the period, or the scheduler cannot
    // satisfy the request and rejects it outright.
    computationNs = std::min(computationNs, periodNs);

    thread_time_constraint_policy_data_t policy;
    policy.period      = static_cast<uint32_t>(periodNs * ticksPerNs);
    policy.computation = static_cast<uint32_t>(computationNs * ticksPerNs);
    // Deadline: the work must be finished within the period, otherwise the
    // next wakeup is already due.
    policy.constraint  = static_cast<uint32_t>(periodNs * ticksPerNs);
    policy.preemptible = 0;

    const kern_return_t result = thread_policy_set(
        pthread_mach_thread_np(pthread_self()),
        THREAD_TIME_CONSTRAINT_POLICY,
        reinterpret_cast<thread_policy_t>(&policy),
        THREAD_TIME_CONSTRAINT_POLICY_COUNT
    );

    if (result != KERN_SUCCESS) {
        fprintf(stderr, "AES67 AudioThreadPriority: THREAD_TIME_CONSTRAINT_POLICY "
                        "failed (kern_return=%d: %s)\n",
                result, mach_error_string(result));
        AES67_LOGF("AudioThreadPriority: THREAD_TIME_CONSTRAINT_POLICY failed (%d: %s)",
                   result, mach_error_string(result));
        return false;
    }

    // Opt out of timer coalescing.
    //
    // macOS batches timer wakeups for threads it considers idle, to save power.
    // Inside a host process that is doing nothing else -- coreaudiod with no
    // application using the device -- that turns a steady 1ms cadence into
    // bursts separated by 30ms stalls, which measured as 2094 packet gaps over
    // 2ms in 30 seconds. Requesting the lowest latency tier asks the scheduler
    // to wake this thread on time rather than when convenient.
    thread_latency_qos_policy_data_t latencyPolicy;
    latencyPolicy.thread_latency_qos_tier = LATENCY_QOS_TIER_0;
    thread_policy_set(pthread_mach_thread_np(pthread_self()),
                      THREAD_LATENCY_QOS_POLICY,
                      reinterpret_cast<thread_policy_t>(&latencyPolicy),
                      THREAD_LATENCY_QOS_POLICY_COUNT);

    // Read the tier back. Requesting it is not the same as getting it, and
    // the difference between tier 0 and the background envelope is 1ms versus
    // 100ms of permitted slop.
    thread_latency_qos_policy_data_t readBack{};
    mach_msg_type_number_t readBackCount = THREAD_LATENCY_QOS_POLICY_COUNT;
    boolean_t getDefault = FALSE;
    if (thread_policy_get(pthread_mach_thread_np(pthread_self()),
                          THREAD_LATENCY_QOS_POLICY,
                          reinterpret_cast<thread_policy_t>(&readBack),
                          &readBackCount, &getDefault) == KERN_SUCCESS) {
        AES67_LOGF("AudioThreadPriority: latency qos tier requested 0, reads back %u",
                   (unsigned)readBack.thread_latency_qos_tier);
    }

    thread_throughput_qos_policy_data_t throughputPolicy;
    throughputPolicy.thread_throughput_qos_tier = THROUGHPUT_QOS_TIER_0;
    thread_policy_set(pthread_mach_thread_np(pthread_self()),
                      THREAD_THROUGHPUT_QOS_POLICY,
                      reinterpret_cast<thread_policy_t>(&throughputPolicy),
                      THREAD_THROUGHPUT_QOS_POLICY_COUNT);

    return true;
}

bool AudioThreadPriority::configureThreadForRealTime(pthread_t thread) {
    // On macOS, use mach thread policies for real-time audio
    thread_extended_policy_data_t extendedPolicy;
    thread_precedence_policy_data_t precedencePolicy;
    thread_affinity_policy_data_t affinityPolicy;

    // Set extended policy for real-time constraints
    extendedPolicy.timeshare = FALSE; // Don't timeshare - run at real-time priority

    kern_return_t result = thread_policy_set(
        pthread_mach_thread_np(thread),
        THREAD_EXTENDED_POLICY,
        (thread_policy_t)&extendedPolicy,
        THREAD_EXTENDED_POLICY_COUNT
    );

    if (result != KERN_SUCCESS) {
        fprintf(stderr, "AES67 AudioThreadPriority: THREAD_EXTENDED_POLICY failed (kern_return=%d: %s), falling back to nice -20\n",
                result, mach_error_string(result));
        // Fallback: try to set nice value
        setpriority(PRIO_PROCESS, 0, -20);
        return false;
    }

    // Set precedence policy for priority
    precedencePolicy.importance = 63; // High priority value (0-63)

    result = thread_policy_set(
        pthread_mach_thread_np(thread),
        THREAD_PRECEDENCE_POLICY,
        (thread_policy_t)&precedencePolicy,
        THREAD_PRECEDENCE_POLICY_COUNT
    );

    if (result != KERN_SUCCESS) {
        fprintf(stderr, "AES67 AudioThreadPriority: THREAD_PRECEDENCE_POLICY failed (kern_return=%d: %s)\n",
                result, mach_error_string(result));
        return false;
    }

    // Optionally set affinity policy (could be used to pin to specific cores)
    // This is optional and may not be needed for basic real-time audio
    affinityPolicy.affinity_tag = 0; // Use default affinity

    result = thread_policy_set(
        pthread_mach_thread_np(thread),
        THREAD_AFFINITY_POLICY,
        (thread_policy_t)&affinityPolicy,
        THREAD_AFFINITY_POLICY_COUNT
    );

    if (result != KERN_SUCCESS) {
        // Affinity tags are not supported at all on Apple Silicon, so this
        // fails for every thread we configure. It is genuinely non-critical,
        // but reporting it each time buries the failures that do matter --
        // several hundred copies of this line accumulated in one session.
        static std::atomic<bool> reported{false};
        if (!reported.exchange(true)) {
            fprintf(stderr, "AES67 AudioThreadPriority: THREAD_AFFINITY_POLICY failed (kern_return=%d: %s) - non-critical, not reported again\n",
                    result, mach_error_string(result));
        }
    }

    return result == KERN_SUCCESS;
}

void AudioThreadPriority::restoreNormalPriority() {
    // Reset to normal scheduling
    thread_extended_policy_data_t extendedPolicy;
    extendedPolicy.timeshare = TRUE; // Timeshare - normal scheduling
    
    thread_policy_set(
        mach_thread_self(),
        THREAD_EXTENDED_POLICY,
        (thread_policy_t)&extendedPolicy,
        THREAD_EXTENDED_POLICY_COUNT
    );
    
    // Restore normal nice value
    setpriority(PRIO_PROCESS, 0, 0);
}

int AudioThreadPriority::getRecommendedSchedulingPolicy() {
    // On macOS, we use Mach thread policies instead of POSIX scheduling
    return SCHED_FIFO;  // This is for reference; actual implementation uses Mach
}

int AudioThreadPriority::getRecommendedPriority() {
    // High priority for audio processing
    return 63;  // Max priority for real-time audio on macOS
}

} // namespace AES67
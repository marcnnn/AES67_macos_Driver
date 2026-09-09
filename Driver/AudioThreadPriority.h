#ifndef AUDIO_THREAD_PRIORITY_H
#define AUDIO_THREAD_PRIORITY_H

#include <pthread.h>
#include <sched.h>
#include <cstdint>

namespace AES67 {

/**
 * Utility class to manage real-time audio thread priorities
 * 
 * Critical for preventing audio dropouts due to thread preemption
 */
class AudioThreadPriority {
public:
    /**
     * Configure the current thread for real-time audio processing
     * @return true if successful, false otherwise
     */
    static bool configureForRealTime();

    /// Join the real-time scheduling class for a thread that must wake on a
    /// fixed period, such as a packet transmit loop.
    ///
    /// configureForRealTime() only marks a thread as non-timeshared and raises
    /// its precedence, which leaves it competing normally for the CPU; a 1ms
    /// wakeup can then land milliseconds late under load. This additionally
    /// installs a time-constraint policy, which is what actually tells the
    /// macOS scheduler to run the thread on a deadline.
    ///
    /// @param periodNs      How often the thread must wake.
    /// @param computationNs Roughly how long its work takes each period.
    static bool configureForRealTimePeriodic(uint64_t periodNs, uint64_t computationNs);
    
    /**
     * Configure a specific thread for real-time audio processing
     * @param thread Thread to configure
     * @return true if successful, false otherwise
     */
    static bool configureThreadForRealTime(pthread_t thread);
    
    /**
     * Restore normal priority to the current thread
     */
    static void restoreNormalPriority();
    
    /**
     * Get the recommended scheduling policy for audio threads
     */
    static int getRecommendedSchedulingPolicy();
    
    /**
     * Get the recommended priority for audio threads
     */
    static int getRecommendedPriority();
};

} // namespace AES67

#endif // AUDIO_THREAD_PRIORITY_H
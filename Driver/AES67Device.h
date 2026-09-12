//
// AES67Device.h
// AES67 macOS Driver - Build #1
// Core Audio device implementation using libASPL
// 128-channel input/output AudioServerPlugIn
//

#pragma once

#include "../Shared/Types.h"
#include "../Shared/RingBuffer.hpp"
#include "../NetworkEngine/StreamManager.h"
#include "../NetworkEngine/RTSafeStreamInterface.h"
#include <aspl/Device.hpp>
#include <aspl/Stream.hpp>
#include <aspl/Context.hpp>
#include <memory>
#include <array>
#include <atomic>

namespace AES67 {

class AES67IOHandler;

//
// AES67 Audio Device
//
// 128-channel bidirectional Core Audio device
// Integrates with macOS Core Audio via AudioServerPlugIn (libASPL)
//
class AES67Device : public aspl::Device {
public:
    static constexpr size_t kNumChannels = 128;

    // Nominal sample rate the device advertises to Core Audio. AES67 runs at
    // 48kHz, so start there rather than inheriting libASPL's 44100 default --
    // otherwise the device reports a nominal rate its own streams do not use.
    static constexpr Float64 kDefaultSampleRate = 48000.0;

    // Supported sample rates
    static constexpr std::array<Float64, 8> kSupportedSampleRates = {
        44100.0, 48000.0, 88200.0, 96000.0,
        176400.0, 192000.0, 352800.0, 384000.0
    };

    // Supported buffer sizes (in samples)
    static constexpr std::array<UInt32, 8> kSupportedBufferSizes = {
        16, 32, 48, 64, 128, 192, 288, 480
    };

    //
    // Constructor
    //
    // The config names the device and decides how many channels it advertises.
    // Defaulted so existing callers and tests keep building the single
    // 128-channel device this driver used to have.
    explicit AES67Device(std::shared_ptr<aspl::Context> context,
                         AudioDeviceConfig deviceConfig = AudioDeviceConfig{});
    ~AES67Device();

    // Initialize device (must be called after construction)
    void Initialize();

    //
    // Device Configuration
    //

    // Get/Set sample rate
    Float64 GetSampleRate() const;
    OSStatus SetSampleRate(Float64 sampleRate);

    // Get available sample rates
    std::vector<AudioValueRange> GetAvailableSampleRates() const override;

    // Get/Set buffer size
    UInt32 GetBufferSize() const;
    OSStatus SetBufferSize(UInt32 bufferSize);

    // Get available buffer sizes
    std::vector<UInt32> GetAvailableBufferSizes() const;

    //
    // Device Information
    //

    std::string GetDeviceName() const;
    std::string GetDeviceManufacturer() const;
    std::string GetDeviceUID() const override;

    // Channels this device advertises to Core Audio. Not kNumChannels: the
    // ring buffers are always allocated for the maximum, but a device
    // configured for 2 channels must report 2, or applications will offer the
    // user 128 outputs of which 126 go nowhere.
    UInt32 GetInputChannelCount() const { return deviceConfig_.channelCount; }
    UInt32 GetOutputChannelCount() const { return deviceConfig_.channelCount; }

    /// The device as configured: name, UID and advertised channel count.
    const AudioDeviceConfig& GetDeviceConfig() const { return deviceConfig_; }

    //
    // Stream Access
    //

    // Get input/output streams
    std::shared_ptr<aspl::Stream> GetInputStream() const { return inputStream_; }
    std::shared_ptr<aspl::Stream> GetOutputStream() const { return outputStream_; }

    //
    // Ring Buffer Access (for NetworkEngine)
    //

    using DeviceChannelBuffers = std::array<SPSCRingBuffer<float>, kNumChannels>;

    DeviceChannelBuffers& GetInputBuffers() { return inputBuffers_; }
    DeviceChannelBuffers& GetOutputBuffers() { return outputBuffers_; }

    //
    // RT-Safe Interface Access
    //

    // Returns the RT-safe interface for use by AES67IOHandler.
    // The interface is created during Initialize() and is valid for the
    // lifetime of this device. Only pass this to RT-safe code paths.
    RTSafeStreamInterface* GetRTInterface() { return rtInterface_.get(); }
    const RTSafeStreamInterface* GetRTInterface() const { return rtInterface_.get(); }

    //
    // Stream Manager Access
    //

    StreamManager* GetStreamManager() { return streamManager_.get(); }
    const StreamManager* GetStreamManager() const { return streamManager_.get(); }

    //
    // Control
    //

    // Start/Stop IO (overrides from aspl::Device)
    OSStatus StartIOImpl(UInt32 clientID, UInt32 startCount) override;
    OSStatus StopIOImpl(UInt32 clientID, UInt32 startCount) override;

    //
    // Media Clock
    //

    /// Report the device's timeline to Core Audio, steered to the rate audio is
    /// actually arriving from the network.
    ///
    /// A virtual device owns its clock, and the default implementation runs it
    /// at exactly the nominal rate off the host clock. That is wrong here: the
    /// sender's clock and this machine's differ by tens of ppm -- measured at
    /// -42.7ppm against the console -- so samples arrive at a rate Core Audio
    /// does not consume at, and the receive ring buffer walks steadily to an
    /// extreme and overruns. At that rate it takes about eight minutes.
    ///
    /// Steering the reported timeline instead of resampling costs no latency
    /// and adds no conversion artifacts.
    OSStatus GetZeroTimeStampImpl(UInt32 clientID,
                                  Float64* outSampleTime,
                                  UInt64* outHostTime,
                                  UInt64* outSeed) override;

    /// Ratio of the reported clock rate to nominal. 1.0 means unsteered.
    double GetClockRatio() const { return clockRatio_.load(std::memory_order_acquire); }

    //
    // Statistics
    //

    uint64_t GetInputUnderrunCount() const { return inputUnderruns_.load(); }
    uint64_t GetOutputUnderrunCount() const { return outputUnderruns_.load(); }
    void ResetStatistics();

private:
    // Internal handlers
    OSStatus OnSetSampleRate(Float64 sampleRate);
    OSStatus OnSetBufferSize(UInt32 bufferSize);

    // Initialize streams and IO handler
    void InitializeStreams();
    void InitializeIOHandler();

    // Calculate optimal ring buffer size based on sample rate
    // Returns size for desired latency (default: 3ms for network jitter tolerance)
    // Result is rounded up to power of 2 for efficient modulo operations
    static size_t CalculateRingBufferSize(Float64 sampleRate, double latencyMs = 3.0);

    // What this instance publishes. Fixed at construction -- Core Audio
    // caches device identity, so changing it later is not a thing.
    const AudioDeviceConfig deviceConfig_;

    // Ring buffers for audio data
    // Network threads write to input buffers, read from output buffers
    // Core Audio thread reads from input buffers, writes to output buffers
    DeviceChannelBuffers inputBuffers_;   // Network → CoreAudio
    DeviceChannelBuffers outputBuffers_;  // CoreAudio → Network

    // Streams
    std::shared_ptr<aspl::Stream> inputStream_;
    std::shared_ptr<aspl::Stream> outputStream_;

    // IO Handler
    std::shared_ptr<AES67IOHandler> ioHandler_;

    // Stream Manager (manages all AES67 network streams)
    std::unique_ptr<StreamManager> streamManager_;

    // RT-safe interface (compile-time boundary for IO handler)
    // Created during Initialize(), references inputBuffers_/outputBuffers_/atomics
    std::unique_ptr<RTSafeStreamInterface> rtInterface_;

    /// Update clockRatio_ from how full the receive ring buffers are.
    /// Buffer occupancy is the error signal rather than PTP: it measures the
    /// rate mismatch that actually matters directly, needs no clock lock, and
    /// carries far less noise than a software-timestamped PTP offset.
    void UpdateClockSteering();

    // --- Media clock steering ---
    std::atomic<double> clockRatio_{1.0};

    // Integral accumulator, in ppm. Only touched by UpdateClockSteering().
    double steeringIntegralPpm_{0.0};

    // The steered timeline is accumulated from scaled increments of the HAL's
    // own, so that a change of ratio bends the clock rather than stepping it.
    // Touched only from GetZeroTimeStampImpl, which the HAL serialises.
    double steeredSampleTime_{0.0};
    double lastRawSampleTime_{0.0};
    bool   steeringInitialised_{false};

    // Fill level the steering aims to hold, as a fraction of buffer capacity.
    // Half leaves equal room to absorb a burst or a gap.
    static constexpr double kTargetFillFraction = 0.5;

    // PI gains, in ppm of clock correction per sample of fill error.
    //
    // The buffer already integrates rate error into fill, so feeding the error
    // into an accumulator as well makes a double integrator, which oscillates:
    // in simulation a pure integral term swung between +11 and +85ppm around a
    // true +42.7. The proportional term sets rate directly from fill error,
    // which is first order and settles; the integral term then removes the
    // offset a proportional-only loop would leave.
    //
    // Simulated against the measured -42.7ppm: settles on +42.70ppm with the
    // buffer at 50.0% and a worst deviation of 3 samples after settling.
    static constexpr double kSteeringProportional = 0.4;
    static constexpr double kSteeringIntegral     = 0.002;

    // No crystal is off by more than this, so a larger correction means the
    // error signal is wrong rather than the clock.
    static constexpr double kMaxSteeringPpm = 200.0;

    // Current configuration
    std::atomic<Float64> currentSampleRate_{kDefaultSampleRate};
    std::atomic<UInt32> currentBufferSize_{64};

    // State
    std::atomic<bool> ioRunning_{false};

    // Statistics
    std::atomic<uint64_t> inputUnderruns_{0};
    std::atomic<uint64_t> outputUnderruns_{0};

    // Resize ring buffers to accommodate new sample rate
    void ResizeRingBuffers(Float64 sampleRate);
};

} // namespace AES67

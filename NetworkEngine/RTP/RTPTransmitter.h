/// @file RTPTransmitter.h
/// @brief RTP packet transmitter with L16/L24 encoding and channel mapping.

#pragma once

#include "../../Shared/Types.h"
#include "../../Shared/RingBuffer.hpp"
#include "../../Driver/SDPParser.h"
#include "../StreamChannelMapper.h"
#include "SimpleRTP.h"
#include "../../Driver/AudioThreadPriority.h"
#include <functional>
#include <thread>
#include <atomic>
#include <memory>

namespace AES67 {

/// Reads audio from device output ring buffers and transmits as RTP multicast packets.
///
/// Single transmit thread using sleep_until pacing for drift-free timing.
/// Sends continuous packets (including silence) for receiver clock recovery.
class RTPTransmitter {
public:
    using DeviceChannelBuffers = std::array<SPSCRingBuffer<float>, 128>;

    /// @param sdp SDP session describing the TX stream configuration.
    /// @param mapping Channel mapping from device channels to stream channels.
    /// @param deviceChannels Reference to device output ring buffers.
    /// @param networkInterface Interface name ("en0") or IP to bind multicast. Empty = default.
    RTPTransmitter(
        const SDPSession& sdp,
        const ChannelMapping& mapping,
        DeviceChannelBuffers& deviceChannels,
        const std::string& networkInterface = ""
    );

    ~RTPTransmitter();

    // Prevent copy/move
    RTPTransmitter(const RTPTransmitter&) = delete;
    RTPTransmitter& operator=(const RTPTransmitter&) = delete;

    //
    // Control
    //

    bool start();
    void stop();
    bool isRunning() const { return running_.load(); }

    //
    // Status
    //

    StatisticsSnapshot getStatistics() const;
    void resetStatistics();

    //
    // Configuration
    //

    bool updateMapping(const ChannelMapping& newMapping);
    const SDPSession& getSDPSession() const { return sdp_; }
    const ChannelMapping& getMapping() const { return mapping_; }

    /// Returns the current media clock time in nanoseconds, on the timescale
    /// of the PTP grandmaster named in the stream's SDP.
    using MediaClockSource = std::function<uint64_t()>;

    /// Supply the clock the RTP timestamps are derived from. AES67 requires the
    /// timestamp of each packet to be the media clock instant of its first
    /// sample, taken from the PTP grandmaster -- that is how a receiver places
    /// our samples on its own playout timeline. A stream whose timestamps merely
    /// count up from zero is decodable but unusable: receivers report it as
    /// carrying no data, because they cannot locate it in time.
    ///
    /// Must be set before start(); the timestamp is anchored there.
    void setMediaClockSource(MediaClockSource source) {
        mediaClockSource_ = std::move(source);
    }

    /// Emit each packet this far ahead of the media time its RTP timestamp
    /// carries.
    ///
    /// A receiver plays a packet at its timestamp plus a fixed link offset,
    /// and discards anything arriving after that. The offset can be small and
    ///, on some receivers, not adjustable -- Dante fixes it at 2ms for AES67 --
    /// so whatever the sender and the receiver's own pipeline consume between
    /// them has to fit inside it. Emitting early buys that headroom back.
    ///
    /// The cost is buffering: sending ahead drains the output ring buffer
    /// sooner, so the producer has correspondingly less slack. Timestamps are
    /// unaffected -- they still name the sampling instant -- so the audio
    /// stays correctly placed in time, it simply leaves sooner.
    ///
    /// Must be set before start().
    void setSendAhead(std::chrono::microseconds ahead) { sendAhead_ = ahead; }
    std::chrono::microseconds getSendAhead() const { return sendAhead_; }

private:
    /// Anchor the media clock counter, or 0 with no clock source. Kept as a
    /// full 64-bit tick count; the RTP timestamp is its low 32 bits.
    uint64_t computeInitialMediaTicks() const;

    /// Convert a media tick count to nanoseconds on the grandmaster timescale.
    uint64_t mediaTicksToNs(uint64_t ticks) const;

    MediaClockSource mediaClockSource_;

    // Transmit thread function
    void transmitLoop();

    // Read audio from device channels and interleave
    bool readDeviceChannels(float* interleavedAudio, size_t frameCount);

    // Audio encoding
    void encodeL16(const float* audio, size_t frameCount, uint8_t* payload);
    void encodeL24(const float* audio, size_t frameCount, uint8_t* payload);

    // Send RTP packet
    void sendPacket(const uint8_t* payload, size_t payloadSize, uint32_t timestamp);

    // Configuration
    SDPSession sdp_;
    ChannelMapping mapping_;
    DeviceChannelBuffers& deviceChannels_;
    std::string networkInterface_;

    // RTP socket
    RTP::RTPSocket rtpSocket_;

    // Threading
    std::thread transmitThread_;
    std::atomic<bool> running_{false};

    // Statistics (atomic operations, no mutex needed for individual updates)
    Statistics stats_;

    // RTP state
    uint16_t sequenceNumber_{0};
    uint32_t timestamp_{0};
    uint32_t ssrc_{0};

    // Timing
    std::chrono::steady_clock::time_point startTime_;
    std::chrono::microseconds packetInterval_;

    // Default to one packet interval: enough to matter to a receiver with a
    // tight link offset, small enough not to eat meaningfully into buffering.
    std::chrono::microseconds sendAhead_{1000};

    // Full-width media clock position of the next packet. timestamp_ is this
    // truncated to 32 bits; this is kept separately so the send schedule can be
    // derived from it without having to undo the wrap.
    uint64_t mediaTicks_{0};

    // Audio buffer (reused to avoid allocations)
    std::vector<float> audioBuffer_;
    std::vector<uint8_t> payloadBuffer_;
};

} // namespace AES67

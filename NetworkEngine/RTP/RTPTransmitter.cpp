//
// RTPTransmitter.cpp
// AES67 macOS Driver - Build #9
// RTP packet transmitter with L16/L24 encoding and channel mapping
//

#include "RTPTransmitter.h"
#include <algorithm>
#include "SimpleRTP.h"
#include "../../Driver/DebugLog.h"
#include <cstring>
#include <random>
#include <chrono>
#include <cerrno>

namespace AES67 {

RTPTransmitter::RTPTransmitter(
    const SDPSession& sdp,
    const ChannelMapping& mapping,
    DeviceChannelBuffers& deviceChannels,
    const std::string& networkInterface
)
    : sdp_(sdp)
    , mapping_(mapping)
    , deviceChannels_(deviceChannels)
    , networkInterface_(networkInterface)
{
    std::memset(&stats_, 0, sizeof(stats_));

    // Generate random SSRC
    std::random_device rd;
    ssrc_ = rd();

    // Pre-allocate buffers to avoid allocations in transmitLoop()
    // Audio buffer: max 512 frames × stream channels
    const size_t maxFrames = 512;
    const size_t maxAudioSamples = maxFrames * sdp_.numChannels;
    audioBuffer_.resize(maxAudioSamples);

    // Payload buffer: RTP header (12 bytes) + max audio payload
    // L24 is largest: 3 bytes/sample × channels × frames
    const size_t maxPayloadSize = 3 * sdp_.numChannels * maxFrames;
    payloadBuffer_.resize(12 + maxPayloadSize);

    // Calculate packet interval based on sample rate
    // AES67 standard: 1ms packets = sample_rate / 1000 samples per packet
    // Example: 48000 Hz → 48 samples/packet → 1ms interval
    const uint64_t intervalUs = 1000; // 1ms in microseconds
    packetInterval_ = std::chrono::microseconds(intervalUs);
}

RTPTransmitter::~RTPTransmitter() {
    stop();
}

bool RTPTransmitter::start() {
    if (running_ || rtpSocket_.isOpen()) {
        AES67_LOGF("RTPTransmitter::start: already running or socket open (stream=%s)",
                   sdp_.sessionName.c_str());
        return false; // Already running
    }

    // Validate SDP configuration
    if (sdp_.connectionAddress.empty() || sdp_.port == 0) {
        AES67_LOGF("RTPTransmitter::start: invalid SDP - address='%s' port=%u (stream=%s)",
                   sdp_.connectionAddress.c_str(), sdp_.port, sdp_.sessionName.c_str());
        return false;
    }

    if (sdp_.numChannels == 0 || sdp_.numChannels > 128) {
        AES67_LOGF("RTPTransmitter::start: invalid channel count %u (stream=%s)",
                   sdp_.numChannels, sdp_.sessionName.c_str());
        return false;
    }

    // Open RTP transmitter socket
    const char* ifaceIP = networkInterface_.empty() ? nullptr : networkInterface_.c_str();
    if (!rtpSocket_.openTransmitter(sdp_.connectionAddress.c_str(), sdp_.port, ifaceIP)) {
        AES67_LOGF("RTPTransmitter::start: socket open failed for %s:%u iface=%s (stream=%s)",
                   sdp_.connectionAddress.c_str(), sdp_.port,
                   networkInterface_.empty() ? "ANY" : networkInterface_.c_str(),
                   sdp_.sessionName.c_str());
        return false;
    }

    sequenceNumber_ = 0;

    // Start transmit thread (elevated priority to prevent audio dropouts).
    //
    // Both the media clock anchor and the send schedule are taken inside the
    // thread, immediately before the loop, rather than here. Spawning the
    // thread and configuring its priority costs milliseconds -- enough that a
    // schedule anchored on the calling thread is already in the past by the
    // time the first packet goes out. Since the loop only ever advances the
    // schedule by one packet interval, that startup lag never drains: every
    // packet for the life of the stream leaves late by however long the thread
    // took to get going, and receivers report the stream as late by exactly
    // that amount.
    running_ = true;
    transmitThread_ = std::thread([this]() {
        // Ask for deadline scheduling on the packet cadence. Marking the
        // thread non-timeshared is not enough on its own: it still competes
        // for the CPU normally, and a 1ms wakeup then lands milliseconds late
        // under load, which a receiver counts as a late packet.
        const uint64_t periodNs =
            static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                packetInterval_).count());
        if (periodNs == 0 ||
            !AudioThreadPriority::configureForRealTimePeriodic(periodNs, periodNs / 4)) {
            AES67_LOGF("RTPTransmitter: failed to set RT priority on transmit thread (stream=%s)",
                       sdp_.sessionName.c_str());
        }

        mediaTicks_ = computeInitialMediaTicks();
        timestamp_ = static_cast<uint32_t>(mediaTicks_ & 0xFFFFFFFFULL);

        // Fallback schedule, used only when there is no media clock to pace
        // against. Started in the past by sendAhead_ so packets still leave
        // early; see setSendAhead().
        startTime_ = std::chrono::steady_clock::now() - sendAhead_;

        transmitLoop();
    });

    return true;
}

void RTPTransmitter::stop() {
    if (!running_) {
        return;
    }

    running_ = false;

    if (transmitThread_.joinable()) {
        transmitThread_.join();
    }

    rtpSocket_.close();
}

StatisticsSnapshot RTPTransmitter::getStatistics() const {
    // Return a consistent snapshot of atomic statistics
    return stats_.snapshot();
}

void RTPTransmitter::resetStatistics() {
    // Reset all atomic counters
    stats_.packetsReceived.store(0, std::memory_order_relaxed);
    stats_.packetsLost.store(0, std::memory_order_relaxed);
    stats_.malformedPackets.store(0, std::memory_order_relaxed);
    stats_.outOfOrderPackets.store(0, std::memory_order_relaxed);
    stats_.underruns.store(0, std::memory_order_relaxed);
    stats_.overruns.store(0, std::memory_order_relaxed);
    stats_.jitterNs.store(0, std::memory_order_relaxed);
    stats_.latencyNs.store(0, std::memory_order_relaxed);
    stats_.bytesReceived.store(0, std::memory_order_relaxed);
    stats_.bytesSent.store(0, std::memory_order_relaxed);
}

bool RTPTransmitter::updateMapping(const ChannelMapping& newMapping) {
    // Validate mapping
    if (newMapping.deviceChannelStart + sdp_.numChannels > 128) {
        return false;
    }

    // Stop, update, restart
    const bool wasRunning = running_;
    if (wasRunning) {
        stop();
    }

    mapping_ = newMapping;

    if (wasRunning) {
        return start();
    }

    return true;
}

void RTPTransmitter::transmitLoop() {
    // Calculate samples per packet (typically 48 for 48kHz @ 1ms)
    const size_t samplesPerPacket = sdp_.framecount;

    auto nextTransmitTime = startTime_;
    bool unsupportedEncodingLogged = false;

    const uint64_t sendAheadNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(sendAhead_).count());
    const uint64_t packetIntervalNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(packetInterval_).count());

    // How often to check the schedule against the media clock. Every packet is
    // too often -- it is the clock's noise that would be tracked, not its rate.
    constexpr int      kPacketsPerMediaSync   = 64;
    constexpr double   kMediaSyncGain         = 0.25;
    constexpr int64_t  kMaxMediaCorrectionNs  = 200000;    // 200us per correction
    constexpr int64_t  kMediaSnapThresholdNs  = 20000000;  // 20ms: slewing is hopeless

    int  packetsSinceMediaSync = kPacketsPerMediaSync;  // check on the first packet

    // Snap on the first check rather than slewing to it. The schedule starts
    // wherever the thread happened to begin, which measured ~4ms away from the
    // media clock; slewing there at the clamped correction rate takes over a
    // second, and every packet sent in the meantime is late. There is nothing
    // to preserve at this point, so take the offset in one step.
    bool resyncToMediaClock = true;

    while (running_) {
        // Pace on the local clock, corrected slowly towards the media clock.
        //
        // Either clock alone is wrong. A purely local schedule advances by a
        // fixed interval per packet and so walks away from the grandmaster at
        // the crystal difference -- tens of ppm here -- until the stream falls
        // outside the receiver's window. But deriving every send instant from
        // the media clock instead puts that clock's own noise straight into
        // the send timing: the estimate carries tens of microseconds of
        // jitter and steps whenever the servo updates, and sleeping for a
        // freshly computed relative duration also folds in each wakeup's
        // overshoot. That shows up as a thin tail of late packets.
        //
        // So: advance an absolute deadline on the local clock, which is smooth,
        // and periodically nudge it towards where the media clock says it
        // should be, which removes the drift. Corrections are a fraction of the
        // measured error and clamped, so clock noise is averaged out rather
        // than transmitted.
        if (mediaClockSource_) {
            if (mediaTicks_ == 0) {
                // PTP may not have locked when the stream started -- it takes a
                // few seconds -- so anchor on the first reading that is
                // actually available rather than being stuck with an unusable
                // zero anchor for the life of the stream.
                const uint64_t anchor = computeInitialMediaTicks();
                if (anchor != 0) {
                    mediaTicks_ = anchor;
                    timestamp_ = static_cast<uint32_t>(mediaTicks_ & 0xFFFFFFFFULL);
                    resyncToMediaClock = true;
                }
            }

            if (++packetsSinceMediaSync >= kPacketsPerMediaSync || resyncToMediaClock) {
                packetsSinceMediaSync = 0;

                const uint64_t nowNs = mediaClockSource_();
                if (nowNs != 0) {
                    // Where the media clock should be as this packet goes out.
                    //
                    // The clock is read here, at the top of the loop, but the
                    // packet does not leave until after the sleep below -- one
                    // packet interval later. Comparing a reading taken now
                    // against where the clock should be at departure is off by
                    // exactly that interval, and since it was also the default
                    // send-ahead, the two cancelled: setSendAhead() had no
                    // effect on when packets actually left. Measured on the
                    // wire, departure sat within 21us of the timestamp instant
                    // with a nominal 1ms of send-ahead configured.
                    const int64_t idealNs = static_cast<int64_t>(mediaTicksToNs(mediaTicks_)) -
                                            static_cast<int64_t>(sendAheadNs) -
                                            static_cast<int64_t>(packetIntervalNs);
                    const int64_t errorNs = static_cast<int64_t>(nowNs) - idealNs;

                    if (resyncToMediaClock || errorNs > kMediaSnapThresholdNs ||
                        errorNs < -kMediaSnapThresholdNs) {
                        // Nothing worth slewing to: a fresh anchor, or the clock
                        // jumped. Place the schedule where the media clock says
                        // this packet is due, in one step. A positive error
                        // means we are late, so the deadline moves earlier.
                        const int64_t clamped = std::clamp(errorNs,
                                                           -kMediaSnapThresholdNs,
                                                           kMediaSnapThresholdNs);
                        nextTransmitTime = std::chrono::steady_clock::now() -
                                           std::chrono::nanoseconds(clamped);
                        resyncToMediaClock = false;
                    } else {
                        int64_t correctionNs =
                            static_cast<int64_t>(static_cast<double>(errorNs) * kMediaSyncGain);
                        correctionNs = std::clamp(correctionNs,
                                                  -kMaxMediaCorrectionNs,
                                                  kMaxMediaCorrectionNs);
                        // Late means the deadline should move earlier.
                        nextTransmitTime -= std::chrono::nanoseconds(correctionNs);
                    }
                }
            }
        }

        std::this_thread::sleep_until(nextTransmitTime);
        nextTransmitTime += packetInterval_;

        // Read audio from device channels (silence-fills on underrun)
        // Always send packets even with empty ring buffers — AES67 requires
        // continuous packet flow for receiver clock recovery
        readDeviceChannels(audioBuffer_.data(), samplesPerPacket);

        // Encode payload based on encoding type
        uint8_t* payload = payloadBuffer_.data();
        size_t payloadSize = 0;

        if (sdp_.encoding == "L16") {
            encodeL16(audioBuffer_.data(), samplesPerPacket, payload);
            payloadSize = samplesPerPacket * sdp_.numChannels * 2; // 2 bytes/sample
        } else if (sdp_.encoding == "L24") {
            encodeL24(audioBuffer_.data(), samplesPerPacket, payload);
            payloadSize = samplesPerPacket * sdp_.numChannels * 3; // 3 bytes/sample
        } else {
            if (!unsupportedEncodingLogged) {
                AES67_LOGF("RTPTransmitter::transmitLoop: unsupported encoding '%s' - no packets will be sent (stream=%s)",
                           sdp_.encoding.c_str(), sdp_.sessionName.c_str());
                unsupportedEncodingLogged = true;
            }
            continue; // Unsupported encoding
        }

        // Send RTP packet
        sendPacket(payload, payloadSize, timestamp_);

        // Advance the media clock position; the RTP timestamp is its low
        // 32 bits and wraps naturally.
        mediaTicks_ += samplesPerPacket;
        timestamp_ = static_cast<uint32_t>(mediaTicks_ & 0xFFFFFFFFULL);

        // Update statistics
        stats_.bytesSent.fetch_add(payloadSize, std::memory_order_relaxed);
    }
}

bool RTPTransmitter::readDeviceChannels(float* interleavedAudio, size_t frameCount) {
    // Validate mapping
    const size_t deviceChannelEnd = mapping_.deviceChannelStart + sdp_.numChannels;
    if (deviceChannelEnd > 128) {
        return false;
    }

    // Stack-allocated temporary buffer for reading each channel
    constexpr size_t kMaxFrames = 512;
    if (frameCount > kMaxFrames) {
        return false;
    }

    float channelBuffer[kMaxFrames];
    bool hadUnderrun = false;

    // Read each device channel and interleave into output
    // Result: [ch0_f0, ch1_f0, ch0_f1, ch1_f1, ...]
    for (size_t streamChannel = 0; streamChannel < sdp_.numChannels; ++streamChannel) {
        const size_t deviceChannel = mapping_.deviceChannelStart + streamChannel;

        // Batch read from ring buffer
        const size_t samplesRead = deviceChannels_[deviceChannel].read(channelBuffer, frameCount);

        if (samplesRead < frameCount) {
            // Ring buffer underrun - fill remainder with silence
            std::memset(&channelBuffer[samplesRead], 0,
                       (frameCount - samplesRead) * sizeof(float));
            hadUnderrun = true;
        }

        // Interleave this channel into output
        for (size_t frame = 0; frame < frameCount; ++frame) {
            interleavedAudio[frame * sdp_.numChannels + streamChannel] = channelBuffer[frame];
        }
    }

    // Return false if we had underrun (indicates audio not ready)
    return !hadUnderrun;
}

void RTPTransmitter::encodeL16(const float* audio, size_t frameCount, uint8_t* payload) {
    // L16: 16-bit big-endian signed PCM
    const size_t totalSamples = frameCount * sdp_.numChannels;

    for (size_t i = 0; i < totalSamples; ++i) {
        // Clamp to [-1.0, 1.0] and convert to int16
        float value = std::max(-1.0f, std::min(1.0f, audio[i]));
        int16_t pcmSample = static_cast<int16_t>(value * 32767.0f);

        // Big-endian encoding
        payload[i * 2 + 0] = (pcmSample >> 8) & 0xFF;
        payload[i * 2 + 1] = pcmSample & 0xFF;
    }
}

void RTPTransmitter::encodeL24(const float* audio, size_t frameCount, uint8_t* payload) {
    // L24: 24-bit big-endian signed PCM
    const size_t totalSamples = frameCount * sdp_.numChannels;

    for (size_t i = 0; i < totalSamples; ++i) {
        // Clamp to [-1.0, 1.0] and convert to int32 (24-bit range)
        float value = std::max(-1.0f, std::min(1.0f, audio[i]));
        int32_t pcmSample = static_cast<int32_t>(value * 8388607.0f); // 2^23 - 1

        // Big-endian 24-bit encoding (only write 3 bytes)
        payload[i * 3 + 0] = (pcmSample >> 16) & 0xFF;
        payload[i * 3 + 1] = (pcmSample >> 8) & 0xFF;
        payload[i * 3 + 2] = pcmSample & 0xFF;
    }
}

uint64_t RTPTransmitter::mediaTicksToNs(uint64_t ticks) const {
    const uint64_t rate = sdp_.sampleRate ? sdp_.sampleRate : 48000;
    // Split so the multiply cannot overflow on a long-running stream.
    const uint64_t seconds = ticks / rate;
    const uint64_t remainder = ticks % rate;
    return seconds * 1000000000ULL + (remainder * 1000000000ULL) / rate;
}

uint64_t RTPTransmitter::computeInitialMediaTicks() const {
    if (!mediaClockSource_) {
        // Nothing to anchor to. The stream will still decode, but a receiver
        // has no way to align it and will treat it as carrying no data.
        AES67_LOGF("RTPTransmitter: no media clock source for '%s'; RTP timestamps "
                   "will not be PTP-aligned and receivers may reject the stream",
                   sdp_.sessionName.c_str());
        return 0;
    }

    const uint64_t ptpNs = mediaClockSource_();
    if (ptpNs == 0) {
        AES67_LOGF("RTPTransmitter: media clock unavailable for '%s'; starting "
                   "timestamps at 0", sdp_.sessionName.c_str());
        return 0;
    }

    // timestamp = media clock time in sample periods, wrapped to 32 bits.
    // Split the conversion so neither term overflows: seconds * rate stays
    // exact, and the sub-second part is scaled before it can lose precision.
    const uint64_t sampleRate = sdp_.sampleRate;
    const uint64_t seconds = ptpNs / 1000000000ULL;
    const uint64_t nanos   = ptpNs % 1000000000ULL;
    const uint64_t ticks   = seconds * sampleRate +
                             (nanos * sampleRate) / 1000000000ULL;

    AES67_LOGF("RTPTransmitter: anchored RTP timestamp for '%s' to media clock (%u)",
               sdp_.sessionName.c_str(),
               static_cast<uint32_t>(ticks & 0xFFFFFFFFULL));
    return ticks;
}

void RTPTransmitter::sendPacket(const uint8_t* payload, size_t payloadSize, uint32_t timestamp) {
    if (!rtpSocket_.isOpen() || !payload || payloadSize == 0) {
        return;
    }

    // Build RTP packet
    RTP::RTPPacket packet;
    packet.header.version = 2;
    packet.header.padding = 0;
    packet.header.extension = 0;
    packet.header.cc = 0;
    packet.header.marker = 0;
    packet.header.payloadType = sdp_.payloadType;
    packet.header.sequenceNumber = sequenceNumber_++;
    packet.header.timestamp = timestamp;
    packet.header.ssrc = ssrc_;
    packet.payload = const_cast<uint8_t*>(payload);
    packet.payloadSize = payloadSize;

    // Send packet
    ssize_t bytesSent = rtpSocket_.send(packet);

    if (bytesSent < 0) {
        // Send failed — count via malformedPackets (repurposed as send error counter for TX)
        uint64_t count = stats_.malformedPackets.fetch_add(1, std::memory_order_relaxed) + 1;
        // Log first occurrence and then every 100th to avoid flooding
        if (count == 1 || count % 100 == 0) {
            AES67_LOGF("RTPTransmitter::sendPacket: send failed #%llu (seq=%u, errno=%d: %s) stream=%s",
                       (unsigned long long)count, sequenceNumber_ - 1,
                       errno, strerror(errno), sdp_.sessionName.c_str());
        }
    }
}

} // namespace AES67

//
// PTPSlave.cpp
// AES67 macOS Driver
// IEEE 1588-2008 PTP Slave-Only Implementation
//
// Implements the four-timestamp offset calculation:
//   t1 = Sync origin timestamp (from Follow_Up in two-step mode)
//   t2 = Sync receive timestamp (our local clock when Sync arrives)
//   t3 = Delay_Req send timestamp (our local clock when we send Delay_Req)
//   t4 = Delay_Req receive timestamp (from Delay_Resp)
//
//   offset    = ((t2 - t1) + (t3 - t4)) / 2
//   pathDelay = ((t2 - t1) - (t3 - t4)) / 2  (same as ((t2-t1)+(t4-t3))/2 )
//

#include "PTPSlave.h"
#include "PTPDiagnostics.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <unistd.h>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <chrono>

namespace AES67 {

// ============================================================================
// IEEE 1588 Constants
// ============================================================================

namespace {
    // PTP multicast addresses (IEEE 1588-2008 Section 13.1)
    constexpr const char* kPTPPrimaryMulticast = "224.0.1.129";   // Default domain
    // Peer delay multicast: "224.0.0.107" (reserved for future peer-delay support)

    // PTP UDP ports (IEEE 1588-2008 Section 13.1)
    constexpr uint16_t kPTPEventPort   = 319;
    constexpr uint16_t kPTPGeneralPort = 320;

    // PTP header size (IEEE 1588-2008 Section 13.3)
    constexpr size_t kPTPHeaderSize = 34;

    // Message body offsets (after header)
    constexpr size_t kTimestampOffset = 34;  // Origin/receive timestamp starts at byte 34

    // Announce message offsets (after header)
    // Note: originTimestamp at offset 34 and currentUtcOffset at 44 are parsed
    // by position but not stored separately — their values are implicit in the
    // grandmaster clock quality fields that follow.
    constexpr size_t kAnnounceGMPriority1Offset = 47;
    constexpr size_t kAnnounceGMClassOffset = 48;
    constexpr size_t kAnnounceGMAccuracyOffset = 49;
    constexpr size_t kAnnounceGMVarianceOffset = 50;
    constexpr size_t kAnnounceGMPriority2Offset = 52;
    constexpr size_t kAnnounceGMIdentityOffset = 53;
    constexpr size_t kAnnounceStepsRemovedOffset = 61;
    constexpr size_t kAnnounceTimeSourceOffset = 63;

    // Minimum message sizes
    constexpr size_t kMinSyncSize = 44;
    constexpr size_t kMinFollowUpSize = 44;
    constexpr size_t kMinDelayRespSize = 54;
    constexpr size_t kMinAnnounceSize = 64;

    // PTP version
    constexpr uint8_t kPTPVersion = 2;

    // Flag field bits
    constexpr uint16_t kFlagTwoStep = 0x0200;

    // Max receive buffer
    constexpr size_t kMaxPTPMessageSize = 1500;

    // Announce timeout multiplier is configured via PTPSlaveConfig::announceTimeoutMultiplier
}

// ============================================================================
// PTPClockIdentity
// ============================================================================

std::string PTPClockIdentity::toString() const {
    std::ostringstream oss;
    for (size_t i = 0; i < 8; ++i) {
        if (i > 0) oss << ':';
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(id[i]);
    }
    return oss.str();
}

PTPClockIdentity PTPClockIdentity::fromMAC(const uint8_t mac[6]) {
    PTPClockIdentity cid;
    // EUI-48 to EUI-64 conversion (insert FF:FE in the middle)
    cid.id[0] = mac[0];
    cid.id[1] = mac[1];
    cid.id[2] = mac[2];
    cid.id[3] = 0xFF;
    cid.id[4] = 0xFE;
    cid.id[5] = mac[3];
    cid.id[6] = mac[4];
    cid.id[7] = mac[5];
    return cid;
}

// ============================================================================
// PTPSlave Construction / Destruction
// ============================================================================

PTPSlave::PTPSlave(const PTPSlaveConfig& config)
    : config_(config)
    , eventSocket_(-1)
    , generalSocket_(-1)
{
    offsetHistory_.fill(0);
    delayHistory_.fill(0);
}

PTPSlave::~PTPSlave() {
    stop();
}

// ============================================================================
// Lifecycle
// ============================================================================

bool PTPSlave::start() {
    if (running_.load(std::memory_order_acquire)) {
        return false;
    }

    // Build our clock identity from the interface MAC
    uint8_t mac[6] = {0};
    if (getInterfaceMAC(mac)) {
        selfPortId_.clockIdentity = PTPClockIdentity::fromMAC(mac);
    } else {
        // Fallback: use random-ish identity
        std::cerr << "[PTPSlave] Warning: Could not get MAC for "
                  << config_.interfaceName << ", using fallback identity" << std::endl;
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        for (int i = 0; i < 8; ++i) {
            selfPortId_.clockIdentity.id[i] = static_cast<uint8_t>((now >> (i * 8)) & 0xFF);
        }
    }
    selfPortId_.portNumber = 1;

    // Create multicast sockets
    if (!createSockets()) {
        std::cerr << "[PTPSlave] Failed to create PTP sockets on "
                  << config_.interfaceName << std::endl;
        return false;
    }

    // Reset state
    hasMaster_ = false;
    locked_.store(false, std::memory_order_release);
    waitingForFollowUp_ = false;
    waitingForDelayResp_ = false;
    consecutiveGoodMeasurements_ = 0;
    offsetHistoryCount_ = 0;
    offsetHistoryIndex_ = 0;
    delayHistoryCount_ = 0;
    delayHistoryIndex_ = 0;
    resetEpochBaseline();
    syncCount_.store(0, std::memory_order_relaxed);
    followUpCount_.store(0, std::memory_order_relaxed);
    delayReqSentCount_.store(0, std::memory_order_relaxed);
    delayRespCount_.store(0, std::memory_order_relaxed);
    announceCount_.store(0, std::memory_order_relaxed);
    domainMismatchCount_.store(0, std::memory_order_relaxed);

    running_.store(true, std::memory_order_release);

    std::cout << "[PTPSlave] Starting PTP slave on " << config_.interfaceName
              << " domain " << config_.domain
              << " (identity: " << selfPortId_.clockIdentity.toString() << ")"
              << std::endl;

    // Start receive thread
    receiveThread_ = std::thread(&PTPSlave::receiveThread, this);

    // Start delay request thread
    delayReqThread_ = std::thread(&PTPSlave::delayReqThread, this);

    return true;
}

void PTPSlave::stop() {
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }

    running_.store(false, std::memory_order_release);

    // Close sockets to unblock recv()
    closeSockets();

    if (receiveThread_.joinable()) {
        receiveThread_.join();
    }
    if (delayReqThread_.joinable()) {
        delayReqThread_.join();
    }

    locked_.store(false, std::memory_order_release);

    std::cout << "[PTPSlave] Stopped. Stats: sync=" << syncCount_.load()
              << " followUp=" << followUpCount_.load()
              << " delayReq=" << delayReqSentCount_.load()
              << " delayResp=" << delayRespCount_.load()
              << " announce=" << announceCount_.load()
              << std::endl;
}

// ============================================================================
// Status Queries
// ============================================================================

std::string PTPSlave::getGrandmasterID() const {
    std::lock_guard<std::mutex> lock(masterMutex_);
    if (hasMaster_) {
        return grandmasterIdentity_.toString();
    }
    return "";
}

void PTPSlave::setMeasurementCallback(PTPMeasurementCallback cb) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    measurementCallback_ = std::move(cb);
}

void PTPSlave::updateDiagnostics(PTPDiagnostics& diag) const {
    diag.isLocked = locked_.load(std::memory_order_acquire);
    diag.currentOffset = static_cast<double>(offsetNs_.load(std::memory_order_acquire));
    diag.offsetNs = offsetNs_.load(std::memory_order_acquire);
    diag.frequencyOffset = frequencyDriftPpb_.load(std::memory_order_acquire) / 1000.0; // PPB to PPM
    diag.currentDomain = config_.domain;

    diag.syncMessagesReceived = syncCount_.load(std::memory_order_relaxed);
    diag.followUpMessagesReceived = followUpCount_.load(std::memory_order_relaxed);
    diag.delayReqMessagesSent = delayReqSentCount_.load(std::memory_order_relaxed);
    diag.delayRespMessagesReceived = delayRespCount_.load(std::memory_order_relaxed);
    diag.announceMessagesReceived = announceCount_.load(std::memory_order_relaxed);
    diag.domainMismatchErrors = domainMismatchCount_.load(std::memory_order_relaxed);

    {
        std::lock_guard<std::mutex> lock(masterMutex_);
        diag.isConnected = hasMaster_;
        if (hasMaster_) {
            diag.masterClockID = grandmasterIdentity_.toString();
            diag.clockClass = static_cast<int>(currentMaster_.grandmasterClockClass);
            diag.clockAccuracy = static_cast<int>(currentMaster_.grandmasterClockAccuracy);
        } else {
            diag.masterClockID = "";
        }
    }
}

// ============================================================================
// Socket Management
// ============================================================================

bool PTPSlave::createSockets() {
    // --- Event socket (port 319) ---
    eventSocket_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (eventSocket_ < 0) {
        std::cerr << "[PTPSlave] Failed to create event socket: "
                  << strerror(errno) << std::endl;
        return false;
    }

    // Allow address reuse (multiple PTP instances or coexistence with other PTP software)
    int reuse = 1;
    setsockopt(eventSocket_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(eventSocket_, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));

    // Enable SO_TIMESTAMP for kernel-level receive timestamps
    int timestampOn = 1;
    setsockopt(eventSocket_, SOL_SOCKET, SO_TIMESTAMP, &timestampOn, sizeof(timestampOn));

    // Set receive timeout to allow periodic check of running_ flag
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 250000; // 250ms
    setsockopt(eventSocket_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Bind to event port
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(kPTPEventPort);

    if (bind(eventSocket_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "[PTPSlave] Failed to bind event socket to port "
                  << kPTPEventPort << ": " << strerror(errno) << std::endl;
        closeSockets();
        return false;
    }

    // Join PTP multicast group on our interface
    struct ip_mreq mreq;
    std::memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = inet_addr(kPTPPrimaryMulticast);

    // Get interface IP address for the multicast join
    struct ifaddrs* ifaddrs_ptr = nullptr;
    if (getifaddrs(&ifaddrs_ptr) == 0) {
        for (struct ifaddrs* ifa = ifaddrs_ptr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr) continue;
            if (ifa->ifa_addr->sa_family == AF_INET &&
                config_.interfaceName == ifa->ifa_name) {
                mreq.imr_interface = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr)->sin_addr;
                break;
            }
        }
        freeifaddrs(ifaddrs_ptr);
    }

    if (setsockopt(eventSocket_, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        std::cerr << "[PTPSlave] Failed to join multicast " << kPTPPrimaryMulticast
                  << " on event socket: " << strerror(errno) << std::endl;
        closeSockets();
        return false;
    }

    // Set outgoing multicast interface
    setsockopt(eventSocket_, IPPROTO_IP, IP_MULTICAST_IF,
               &mreq.imr_interface, sizeof(mreq.imr_interface));

    // Set multicast TTL
    uint8_t ttl = 128;
    setsockopt(eventSocket_, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));

    // Disable multicast loopback
    uint8_t loop = 0;
    setsockopt(eventSocket_, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));

    // --- General socket (port 320) ---
    generalSocket_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (generalSocket_ < 0) {
        std::cerr << "[PTPSlave] Failed to create general socket: "
                  << strerror(errno) << std::endl;
        closeSockets();
        return false;
    }

    setsockopt(generalSocket_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(generalSocket_, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));

    // Receive timeout for general socket
    setsockopt(generalSocket_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Bind to general port
    struct sockaddr_in gaddr;
    std::memset(&gaddr, 0, sizeof(gaddr));
    gaddr.sin_family = AF_INET;
    gaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    gaddr.sin_port = htons(kPTPGeneralPort);

    if (bind(generalSocket_, reinterpret_cast<struct sockaddr*>(&gaddr), sizeof(gaddr)) < 0) {
        std::cerr << "[PTPSlave] Failed to bind general socket to port "
                  << kPTPGeneralPort << ": " << strerror(errno) << std::endl;
        closeSockets();
        return false;
    }

    // Join multicast on general socket too
    if (setsockopt(generalSocket_, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        std::cerr << "[PTPSlave] Failed to join multicast " << kPTPPrimaryMulticast
                  << " on general socket: " << strerror(errno) << std::endl;
        closeSockets();
        return false;
    }

    std::cout << "[PTPSlave] Sockets created: event=" << kPTPEventPort
              << " general=" << kPTPGeneralPort
              << " multicast=" << kPTPPrimaryMulticast << std::endl;

    return true;
}

void PTPSlave::closeSockets() {
    if (eventSocket_ >= 0) {
        close(eventSocket_);
        eventSocket_ = -1;
    }
    if (generalSocket_ >= 0) {
        close(generalSocket_);
        generalSocket_ = -1;
    }
}

// ============================================================================
// Receive Thread — handles Sync (event), Follow_Up (general), Announce
// ============================================================================

void PTPSlave::receiveThread() {
    uint8_t buf[kMaxPTPMessageSize];

    while (running_.load(std::memory_order_acquire)) {
        // Use select() to monitor both sockets
        fd_set readfds;
        FD_ZERO(&readfds);

        int maxfd = -1;
        if (eventSocket_ >= 0) {
            FD_SET(eventSocket_, &readfds);
            maxfd = std::max(maxfd, eventSocket_);
        }
        if (generalSocket_ >= 0) {
            FD_SET(generalSocket_, &readfds);
            maxfd = std::max(maxfd, generalSocket_);
        }

        if (maxfd < 0) break;

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 250000; // 250ms timeout

        int ret = select(maxfd + 1, &readfds, nullptr, nullptr, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ret == 0) continue; // Timeout

        // Check event socket (Sync, Delay_Resp)
        if (eventSocket_ >= 0 && FD_ISSET(eventSocket_, &readfds)) {
            // Use recvmsg to get kernel timestamp
            struct msghdr msg;
            struct iovec iov;
            char control[256];

            iov.iov_base = buf;
            iov.iov_len = sizeof(buf);
            msg.msg_name = nullptr;
            msg.msg_namelen = 0;
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control;
            msg.msg_controllen = sizeof(control);
            msg.msg_flags = 0;

            ssize_t n = recvmsg(eventSocket_, &msg, 0);
            if (n >= static_cast<ssize_t>(kPTPHeaderSize)) {
                // Extract kernel receive timestamp if available
                uint64_t receiveTimeNs = getSystemTimeNs(); // fallback
                struct cmsghdr* cmsg;
                for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
                     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                    if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMP) {
                        struct timeval* tvp = reinterpret_cast<struct timeval*>(CMSG_DATA(cmsg));
                        receiveTimeNs = static_cast<uint64_t>(tvp->tv_sec) * 1000000000ULL +
                                        static_cast<uint64_t>(tvp->tv_usec) * 1000ULL;
                        break;
                    }
                }

                PTPHeader header;
                if (parseHeader(buf, static_cast<size_t>(n), header)) {
                    // Domain check
                    if (header.domainNumber != config_.domain) {
                        domainMismatchCount_.fetch_add(1, std::memory_order_relaxed);
                    } else {
                        switch (header.getMessageType()) {
                            case PTPMessageType::Sync:
                                handleSync(header, buf, static_cast<size_t>(n), receiveTimeNs);
                                break;
                            case PTPMessageType::Delay_Resp:
                                handleDelayResp(header, buf, static_cast<size_t>(n));
                                break;
                            default:
                                break;
                        }
                    }
                }
            }
        }

        // Check general socket (Follow_Up, Announce)
        if (generalSocket_ >= 0 && FD_ISSET(generalSocket_, &readfds)) {
            ssize_t n = recv(generalSocket_, buf, sizeof(buf), 0);
            if (n >= static_cast<ssize_t>(kPTPHeaderSize)) {
                PTPHeader header;
                if (parseHeader(buf, static_cast<size_t>(n), header)) {
                    // Domain check
                    if (header.domainNumber != config_.domain) {
                        domainMismatchCount_.fetch_add(1, std::memory_order_relaxed);
                    } else {
                        switch (header.getMessageType()) {
                            case PTPMessageType::Follow_Up:
                                handleFollowUp(header, buf, static_cast<size_t>(n));
                                break;
                            case PTPMessageType::Announce:
                                handleAnnounce(header, buf, static_cast<size_t>(n));
                                break;
                            default:
                                break;
                        }
                    }
                }
            }
        }

        // Check for announce timeout (master lost)
        {
            std::lock_guard<std::mutex> lock(masterMutex_);
            if (hasMaster_) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - currentMaster_.lastReceived).count();
                int timeoutMs = config_.announceIntervalMs * config_.announceTimeoutMultiplier;
                if (elapsed > timeoutMs) {
                    std::cerr << "[PTPSlave] Announce timeout — master lost after "
                              << elapsed << "ms" << std::endl;
                    hasMaster_ = false;
                    locked_.store(false, std::memory_order_release);
                    consecutiveGoodMeasurements_ = 0;
                }
            }
        }
    }
}

// ============================================================================
// Delay Request Thread
// ============================================================================

void PTPSlave::delayReqThread() {
    while (running_.load(std::memory_order_acquire)) {
        // Only send Delay_Req if we have a master and have received at least one Sync
        bool shouldSend = false;
        {
            std::lock_guard<std::mutex> lock(masterMutex_);
            shouldSend = hasMaster_;
        }
        {
            std::lock_guard<std::mutex> lock(syncMutex_);
            shouldSend = shouldSend && (syncCount_.load(std::memory_order_relaxed) > 0);
        }

        if (shouldSend) {
            sendDelayReq();
        }

        // Sleep for the configured delay request interval
        auto sleepTime = std::chrono::milliseconds(config_.delayReqIntervalMs);
        auto deadline = std::chrono::steady_clock::now() + sleepTime;

        while (running_.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
}

// ============================================================================
// Message Parsing
// ============================================================================

bool PTPSlave::parseHeader(const uint8_t* data, size_t len, PTPHeader& header) {
    if (len < kPTPHeaderSize) return false;

    header.transportAndType = data[0];
    header.versionPTP = data[1] & 0x0F;

    // Verify PTP version
    if (header.versionPTP != kPTPVersion) return false;

    header.messageLength = (static_cast<uint16_t>(data[2]) << 8) | data[3];
    header.domainNumber = data[4];
    header.reserved1 = data[5];
    header.flagField = (static_cast<uint16_t>(data[6]) << 8) | data[7];

    // Correction field: 8 bytes, signed, nanoseconds * 2^16
    header.correctionField = 0;
    for (int i = 0; i < 8; ++i) {
        header.correctionField = (header.correctionField << 8) | data[8 + i];
    }

    header.reserved2 = 0;
    for (int i = 0; i < 4; ++i) {
        header.reserved2 = (header.reserved2 << 8) | data[16 + i];
    }

    parsePortIdentity(data, 20, header.sourcePortIdentity);

    header.sequenceId = (static_cast<uint16_t>(data[30]) << 8) | data[31];
    header.controlField = data[32];
    header.logMessageInterval = static_cast<int8_t>(data[33]);

    return true;
}

bool PTPSlave::parseTimestamp(const uint8_t* data, size_t offset, PTPTimestamp& ts) {
    ts.secondsHi = (static_cast<uint16_t>(data[offset]) << 8) |
                    data[offset + 1];
    ts.secondsLo = (static_cast<uint32_t>(data[offset + 2]) << 24) |
                    (static_cast<uint32_t>(data[offset + 3]) << 16) |
                    (static_cast<uint32_t>(data[offset + 4]) << 8) |
                    data[offset + 5];
    ts.nanoseconds = (static_cast<uint32_t>(data[offset + 6]) << 24) |
                     (static_cast<uint32_t>(data[offset + 7]) << 16) |
                     (static_cast<uint32_t>(data[offset + 8]) << 8) |
                     data[offset + 9];
    return true;
}

void PTPSlave::parseClockIdentity(const uint8_t* data, size_t offset, PTPClockIdentity& id) {
    for (int i = 0; i < 8; ++i) {
        id.id[i] = data[offset + i];
    }
}

void PTPSlave::parsePortIdentity(const uint8_t* data, size_t offset, PTPPortIdentity& pid) {
    parseClockIdentity(data, offset, pid.clockIdentity);
    pid.portNumber = (static_cast<uint16_t>(data[offset + 8]) << 8) | data[offset + 9];
}

// ============================================================================
// Message Handlers
// ============================================================================

void PTPSlave::handleSync(const PTPHeader& header, const uint8_t* data, size_t len,
                           uint64_t receiveTimeNs) {
    if (len < kMinSyncSize) return;

    syncCount_.fetch_add(1, std::memory_order_relaxed);

    bool isTwoStep = (header.flagField & kFlagTwoStep) != 0;

    bool canCalculate = false;

    {
        std::lock_guard<std::mutex> lock(syncMutex_);

        // Store t2 (our receive timestamp)
        t2_receiveTimeNs_ = receiveTimeNs;
        lastSyncSequenceId_ = header.sequenceId;
        syncCorrectionField_ = header.correctionField;

        if (isTwoStep) {
            // Two-step: wait for Follow_Up with the precise t1
            waitingForFollowUp_ = true;
            // Parse origin timestamp from Sync (informational only in two-step)
            parseTimestamp(data, kTimestampOffset, syncOriginTimestamp_);
        } else {
            // One-step: origin timestamp in Sync IS t1
            parseTimestamp(data, kTimestampOffset, t1_syncOriginTimestamp_);
            waitingForFollowUp_ = false;

            // Can compute offset immediately with existing delay
            canCalculate = true;
        }
    }

    // calculateOffsetAndDelay() takes syncMutex_ and delayMutex_ itself, so it
    // must be called with both released.
    if (canCalculate) {
        calculateOffsetAndDelay();
    }
}

void PTPSlave::handleFollowUp(const PTPHeader& header, const uint8_t* data, size_t len) {
    if (len < kMinFollowUpSize) return;

    followUpCount_.fetch_add(1, std::memory_order_relaxed);

    {
        std::lock_guard<std::mutex> lock(syncMutex_);

        // Follow_Up must match the Sync we're waiting for
        if (!waitingForFollowUp_) return;
        if (header.sequenceId != lastSyncSequenceId_) return;

        // Parse the precise origin timestamp (t1)
        parseTimestamp(data, kTimestampOffset, t1_syncOriginTimestamp_);

        // Add Follow_Up correction to Sync correction
        // Both are in nanoseconds * 2^16 fixed point
        int64_t totalCorrectionFixed = syncCorrectionField_ + header.correctionField;

        // Convert correction from fixed-point (ns * 2^16) to nanoseconds
        int64_t correctionNs = totalCorrectionFixed >> 16;

        // Apply correction to t1
        uint64_t t1Ns = t1_syncOriginTimestamp_.toNanoseconds();
        t1Ns += static_cast<uint64_t>(correctionNs);
        t1_syncOriginTimestamp_ = PTPTimestamp(t1Ns);

        waitingForFollowUp_ = false;
    }

    // Now we have t1 and t2 — compute offset (using existing path delay).
    // calculateOffsetAndDelay() re-acquires syncMutex_, so the lock above must
    // be released before calling it.
    calculateOffsetAndDelay();
}

void PTPSlave::handleDelayResp(const PTPHeader& header, const uint8_t* data, size_t len) {
    if (len < kMinDelayRespSize) return;

    delayRespCount_.fetch_add(1, std::memory_order_relaxed);

    {
        std::lock_guard<std::mutex> lock(delayMutex_);

        // Must match our Delay_Req
        if (!waitingForDelayResp_) return;
        if (header.sequenceId != delayReqSequenceId_) return;

        // Verify the requesting port identity matches ours (bytes 44-53)
        PTPPortIdentity requestingPort;
        parsePortIdentity(data, 44, requestingPort);
        if (!(requestingPort == selfPortId_)) return;

        // Parse t4 (master's receive timestamp of our Delay_Req)
        parseTimestamp(data, kTimestampOffset, t4_delayRespReceiveTimestamp_);

        // Apply correction field
        int64_t correctionNs = header.correctionField >> 16;
        uint64_t t4Ns = t4_delayRespReceiveTimestamp_.toNanoseconds();
        t4Ns += static_cast<uint64_t>(correctionNs);
        t4_delayRespReceiveTimestamp_ = PTPTimestamp(t4Ns);

        waitingForDelayResp_ = false;
    }

    // Now we have all four timestamps — recalculate with full path delay.
    // calculateOffsetAndDelay() acquires delayMutex_ itself, so the lock above
    // must be released before calling it.
    calculateOffsetAndDelay();
}

void PTPSlave::handleAnnounce(const PTPHeader& header, const uint8_t* data, size_t len) {
    if (len < kMinAnnounceSize) return;

    announceCount_.fetch_add(1, std::memory_order_relaxed);

    // Parse announce data
    PTPAnnounceData announce;
    announce.masterPortId = header.sourcePortIdentity;
    announce.grandmasterPriority1 = data[kAnnounceGMPriority1Offset];
    announce.grandmasterClockClass = data[kAnnounceGMClassOffset];
    announce.grandmasterClockAccuracy = data[kAnnounceGMAccuracyOffset];
    announce.grandmasterOffsetScaledLogVariance =
        (static_cast<uint16_t>(data[kAnnounceGMVarianceOffset]) << 8) |
        data[kAnnounceGMVarianceOffset + 1];
    announce.grandmasterPriority2 = data[kAnnounceGMPriority2Offset];
    parseClockIdentity(data, kAnnounceGMIdentityOffset, announce.grandmasterIdentity);
    announce.stepsRemoved =
        (static_cast<uint16_t>(data[kAnnounceStepsRemovedOffset]) << 8) |
        data[kAnnounceStepsRemovedOffset + 1];
    announce.timeSource = data[kAnnounceTimeSourceOffset];
    announce.logAnnounceInterval = header.logMessageInterval;
    announce.lastReceived = std::chrono::steady_clock::now();

    std::lock_guard<std::mutex> lock(masterMutex_);

    if (!hasMaster_) {
        // Accept this master (simplified BMCA — first announce wins for slave-only)
        currentMaster_ = announce;
        grandmasterIdentity_ = announce.grandmasterIdentity;
        hasMaster_ = true;

        clockClass_.store(announce.grandmasterClockClass, std::memory_order_release);
        clockAccuracy_.store(announce.grandmasterClockAccuracy, std::memory_order_release);

        std::cout << "[PTPSlave] Accepted master: "
                  << announce.grandmasterIdentity.toString()
                  << " class=" << static_cast<int>(announce.grandmasterClockClass)
                  << " accuracy=0x" << std::hex << static_cast<int>(announce.grandmasterClockAccuracy)
                  << std::dec << std::endl;
    } else {
        // Simple BMCA: prefer lower priority1, then lower class, then lower priority2
        bool isBetter = false;
        if (announce.grandmasterPriority1 < currentMaster_.grandmasterPriority1) {
            isBetter = true;
        } else if (announce.grandmasterPriority1 == currentMaster_.grandmasterPriority1) {
            if (announce.grandmasterClockClass < currentMaster_.grandmasterClockClass) {
                isBetter = true;
            } else if (announce.grandmasterClockClass == currentMaster_.grandmasterClockClass) {
                if (announce.grandmasterPriority2 < currentMaster_.grandmasterPriority2) {
                    isBetter = true;
                }
            }
        }

        if (isBetter) {
            std::cout << "[PTPSlave] Switching to better master: "
                      << announce.grandmasterIdentity.toString() << std::endl;
            currentMaster_ = announce;
            grandmasterIdentity_ = announce.grandmasterIdentity;
            clockClass_.store(announce.grandmasterClockClass, std::memory_order_release);
            clockAccuracy_.store(announce.grandmasterClockAccuracy, std::memory_order_release);

            // Reset lock on master change. The new master has its own epoch,
            // so the old baseline and the filter history built against it are
            // both meaningless now.
            locked_.store(false, std::memory_order_release);
            consecutiveGoodMeasurements_ = 0;
            resetEpochBaseline();
        } else if (announce.grandmasterIdentity == grandmasterIdentity_) {
            // Same master, refresh timeout
            currentMaster_.lastReceived = announce.lastReceived;
        }
    }
}

// ============================================================================
// Delay Request Transmission
// ============================================================================

bool PTPSlave::sendDelayReq() {
    if (eventSocket_ < 0) return false;

    // Build Delay_Req message (44 bytes: 34 header + 10 timestamp)
    uint8_t msg[44];
    std::memset(msg, 0, sizeof(msg));

    uint16_t seqId;
    {
        std::lock_guard<std::mutex> lock(delayMutex_);
        seqId = delayReqSequenceId_++;
    }

    // Header
    msg[0] = static_cast<uint8_t>(PTPMessageType::Delay_Req); // transportSpecific=0 | messageType
    msg[1] = kPTPVersion;
    msg[2] = 0; // messageLength high byte
    msg[3] = 44; // messageLength low byte
    msg[4] = static_cast<uint8_t>(config_.domain);
    // flags = 0
    // correction = 0
    // reserved = 0

    // Source port identity (bytes 20-29)
    for (int i = 0; i < 8; ++i) {
        msg[20 + i] = selfPortId_.clockIdentity.id[i];
    }
    msg[28] = static_cast<uint8_t>((selfPortId_.portNumber >> 8) & 0xFF);
    msg[29] = static_cast<uint8_t>(selfPortId_.portNumber & 0xFF);

    // Sequence ID (bytes 30-31)
    msg[30] = static_cast<uint8_t>((seqId >> 8) & 0xFF);
    msg[31] = static_cast<uint8_t>(seqId & 0xFF);

    // Control field = 1 for Delay_Req
    msg[32] = 1;

    // logMessageInterval = 0x7F (not applicable)
    msg[33] = 0x7F;

    // Origin timestamp (bytes 34-43) = 0 (we use t3 from our send time)

    // Record t3 right before sending
    uint64_t t3 = getSystemTimeNs();

    // Send to multicast
    struct sockaddr_in dest;
    std::memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(kPTPPrimaryMulticast);
    dest.sin_port = htons(kPTPEventPort);

    ssize_t sent = sendto(eventSocket_, msg, sizeof(msg), 0,
                          reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest));
    if (sent < 0) {
        std::cerr << "[PTPSlave] Failed to send Delay_Req: "
                  << strerror(errno) << std::endl;
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(delayMutex_);
        t3_delayReqSendTimeNs_ = t3;
        waitingForDelayResp_ = true;
    }

    delayReqSentCount_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

// ============================================================================
// Offset and Delay Calculation
// ============================================================================

void PTPSlave::resetEpochBaseline() {
    // Only ever called from the receive thread (or before it starts), so the
    // non-atomic filter state below needs no additional locking.
    epochBaselineValid_.store(false, std::memory_order_release);
    epochBaselineNs_.store(0, std::memory_order_release);
    rawOffsetNs_.store(0, std::memory_order_release);
    frequencyDriftPpb_.store(0.0, std::memory_order_release);
    offsetHistoryCount_ = 0;
    offsetHistoryIndex_ = 0;
    lastDriftCalcTimeNs_ = 0;
    lastDriftCalcOffsetNs_ = 0;
    resetServo();
}

void PTPSlave::resetServo() {
    servoFreqPpb_.store(0.0, std::memory_order_release);
    servoCorrectionNs_.store(0, std::memory_order_release);
    servoLastUpdateMonoNs_.store(0, std::memory_order_release);
    servoFreqSeeded_.store(false, std::memory_order_release);
    servoStarted_ = false;
    servoHistoryIndex_ = 0;
    servoHistoryCount_ = 0;
    servoHistoryOriginNs_ = 0;
}

// Least-squares slope through the recent (time, offset) samples.
//
// The offset between the two clocks is a straight line with slope equal to
// their frequency difference, buried in per-measurement jitter. Fitting the
// line over many samples recovers the slope far more accurately than
// differencing any two points: the jitter averages down, the ramp does not.
bool PTPSlave::estimateFrequencyPpb(double& ppbOut) const {
    const size_t n = servoHistoryCount_;
    if (n < config_.servoMinFrequencySamples || n < 2) {
        return false;
    }

    double sumT = 0.0, sumY = 0.0;
    for (size_t i = 0; i < n; ++i) {
        sumT += servoHistoryTimeS_[i];
        sumY += servoHistoryOffsetNs_[i];
    }
    const double meanT = sumT / static_cast<double>(n);
    const double meanY = sumY / static_cast<double>(n);

    double covTY = 0.0, varT = 0.0;
    for (size_t i = 0; i < n; ++i) {
        const double dT = servoHistoryTimeS_[i] - meanT;
        covTY += dT * (servoHistoryOffsetNs_[i] - meanY);
        varT  += dT * dT;
    }
    if (varT <= 0.0) return false;

    // Slope is ns per second, which is ppb directly.
    ppbOut = covTY / varT;
    return true;
}

// Feed one measurement to the virtual clock servo and return the residual.
//
// The servo maintains a correction that tracks `measuredNs` -- the offset
// between the local clock and the master. Because the two crystals run at
// slightly different rates, `measuredNs` is a ramp; the correction follows it,
// and what is left over (the residual) is the part the servo has not accounted
// for. That residual is what callers should see as "offset from master": it
// stays near zero while tracking holds, instead of growing forever.
//
// Only ever called from the receive thread.
int64_t PTPSlave::updateServo(int64_t measuredNs) {
    const uint64_t nowMono = getMonotonicTimeNs();

    if (!servoStarted_) {
        // Nothing to difference against yet. Adopt the measurement as the
        // starting correction so the first residual is zero rather than the
        // whole epoch-normalised offset.
        servoStarted_ = true;
        servoHistoryOriginNs_ = nowMono;
        servoCorrectionNs_.store(measuredNs, std::memory_order_release);
        servoLastUpdateMonoNs_.store(nowMono, std::memory_order_release);
    }

    // Record the sample for the frequency fit.
    const size_t capacity = std::min(config_.servoFrequencyWindow, kServoHistoryCapacity);
    servoHistoryTimeS_[servoHistoryIndex_] =
        static_cast<double>(nowMono - servoHistoryOriginNs_) / 1e9;
    servoHistoryOffsetNs_[servoHistoryIndex_] = static_cast<double>(measuredNs);
    servoHistoryIndex_ = (servoHistoryIndex_ + 1) % capacity;
    if (servoHistoryCount_ < capacity) servoHistoryCount_++;

    const uint64_t lastMono = servoLastUpdateMonoNs_.load(std::memory_order_acquire);
    const double dt = static_cast<double>(nowMono - lastMono) / 1e9;
    if (dt < 0.0) {
        // Out-of-order measurement; nothing useful to do.
        return measuredNs - servoCorrectionNs_.load(std::memory_order_acquire);
    }

    double freqPpb = servoFreqPpb_.load(std::memory_order_acquire);
    int64_t correction = servoCorrectionNs_.load(std::memory_order_acquire);

    // Refresh the frequency estimate from the fit. This replaces the estimate
    // outright rather than nudging it, because the fit already averages over
    // the whole window -- there is no accumulated state to preserve and so no
    // way for it to wind up.
    double fittedPpb = 0.0;
    if (estimateFrequencyPpb(fittedPpb)) {
        freqPpb = std::clamp(fittedPpb,
                             -config_.servoMaxFrequencyPpb,
                             config_.servoMaxFrequencyPpb);
        if (!servoFreqSeeded_.exchange(true, std::memory_order_acq_rel)) {
            std::cout << "[PTPSlave] Servo frequency acquired: " << freqPpb
                      << " ppb over " << servoHistoryCount_ << " samples (local clock runs "
                      << (freqPpb >= 0.0 ? "fast" : "slow")
                      << " relative to master)" << std::endl;
        }
    }

    // Advance the correction at the rate the clocks differ by. 1 ppb is 1 ns
    // per second, so ppb * seconds gives ns directly.
    correction += static_cast<int64_t>(freqPpb * dt);

    int64_t residual = measuredNs - correction;

    if (residual > config_.servoStepThresholdNs ||
        residual < -config_.servoStepThresholdNs) {
        // Too far out to slew. Step the correction onto the measurement and
        // start the frequency estimate over.
        std::cout << "[PTPSlave] Servo step: residual " << residual
                  << "ns exceeds threshold - re-acquiring" << std::endl;
        correction = measuredNs;
        residual = 0;
        freqPpb = 0.0;
        servoFreqSeeded_.store(false, std::memory_order_release);
        servoHistoryIndex_ = 0;
        servoHistoryCount_ = 0;
        servoHistoryOriginNs_ = nowMono;
        locked_.store(false, std::memory_order_release);
        consecutiveGoodMeasurements_ = 0;
    } else {
        // Phase term: pull the correction towards the measurement. The
        // frequency term above handles the ramp, so this only has to absorb
        // what is left, and can stay gentle enough not to inject jitter into
        // the virtual clock.
        correction += static_cast<int64_t>(config_.servoProportional *
                                           static_cast<double>(residual));
    }

    servoFreqPpb_.store(freqPpb, std::memory_order_release);
    servoCorrectionNs_.store(correction, std::memory_order_release);
    servoLastUpdateMonoNs_.store(nowMono, std::memory_order_release);

    return residual;
}

uint64_t PTPSlave::getMasterTimeNs() const {
    // master time = local time - epoch difference - servo correction, with the
    // correction projected forward from the last update at the current rate.
    const int64_t local = static_cast<int64_t>(getSystemTimeNs());
    const int64_t epoch = epochBaselineNs_.load(std::memory_order_acquire);
    int64_t correction = servoCorrectionNs_.load(std::memory_order_acquire);

    const uint64_t lastMono = servoLastUpdateMonoNs_.load(std::memory_order_acquire);
    if (lastMono != 0) {
        const double dt = static_cast<double>(getMonotonicTimeNs() - lastMono) / 1e9;
        correction += static_cast<int64_t>(
            servoFreqPpb_.load(std::memory_order_acquire) * dt);
    }

    return static_cast<uint64_t>(local - epoch - correction);
}

void PTPSlave::calculateOffsetAndDelay() {
    // We need t1, t2 to compute offset (using existing delay estimate).
    // When we also have t3, t4 we compute the full offset+delay.
    //
    // offset    = ((t2 - t1) + (t3 - t4)) / 2
    // pathDelay = ((t2 - t1) - (t3 - t4)) / 2
    //
    // With only t1, t2:
    // offset_approx = (t2 - t1) - pathDelay

    int64_t t1Ns = 0;
    int64_t t3Ns = 0;
    uint64_t t2Ns = 0;

    {
        std::lock_guard<std::mutex> lock(syncMutex_);
        if (waitingForFollowUp_) return; // Don't have t1 yet
        if (t1_syncOriginTimestamp_.isZero()) return;
        t1Ns = static_cast<int64_t>(t1_syncOriginTimestamp_.toNanoseconds());
        t2Ns = t2_receiveTimeNs_;
    }

    int64_t t2SignedNs = static_cast<int64_t>(t2Ns);

    // Check if we have delay measurement (t3, t4)
    bool haveDelay = false;
    int64_t t4Ns = 0;
    {
        std::lock_guard<std::mutex> lock(delayMutex_);
        if (!waitingForDelayResp_ && t3_delayReqSendTimeNs_ != 0 &&
            !t4_delayRespReceiveTimestamp_.isZero()) {
            haveDelay = true;
            t3Ns = static_cast<int64_t>(t3_delayReqSendTimeNs_);
            t4Ns = static_cast<int64_t>(t4_delayRespReceiveTimestamp_.toNanoseconds());
        }
    }

    int64_t offset = 0;
    int64_t delay = 0;

    if (haveDelay) {
        // Full four-timestamp calculation
        // offset    = ((t2 - t1) + (t3 - t4)) / 2
        // pathDelay = ((t2 - t1) + (t4 - t3)) / 2
        int64_t ms2slave = t2SignedNs - t1Ns;    // t2 - t1
        int64_t slave2m = t4Ns - t3Ns;           // t4 - t3

        offset = (ms2slave - slave2m) / 2;
        delay  = (ms2slave + slave2m) / 2;

        // Filter path delay (use minimum of recent values — path delay shouldn't go negative)
        if (delay >= 0) {
            delayHistory_[delayHistoryIndex_] = delay;
            delayHistoryIndex_ = (delayHistoryIndex_ + 1) % kDelayFilterSize;
            if (delayHistoryCount_ < kDelayFilterSize) delayHistoryCount_++;

            // Use filtered delay (median-like: use minimum of recent values to reject outliers)
            int64_t minDelay = delay;
            for (size_t i = 0; i < delayHistoryCount_; ++i) {
                minDelay = std::min(minDelay, delayHistory_[i]);
            }
            pathDelayNs_.store(minDelay, std::memory_order_release);
        }
    } else {
        // Approximate offset using stored path delay
        int64_t storedDelay = pathDelayNs_.load(std::memory_order_acquire);
        offset = (t2SignedNs - t1Ns) - storedDelay;
    }

    // The raw offset carries any difference between the master's PTP epoch and
    // our system clock epoch. Keep it for diagnostics before normalising.
    rawOffsetNs_.store(offset, std::memory_order_release);

    if (config_.normalizeEpoch) {
        if (!epochBaselineValid_.load(std::memory_order_acquire)) {
            // The first usable measurement decides whether the master shares
            // our epoch. Only an implausibly large difference is treated as an
            // epoch difference — a small one is a real offset worth reporting.
            const bool differentEpoch = (offset > config_.epochThresholdNs ||
                                         offset < -config_.epochThresholdNs);
            const int64_t baseline = differentEpoch ? offset : 0;

            epochBaselineNs_.store(baseline, std::memory_order_release);
            epochBaselineValid_.store(true, std::memory_order_release);
            offsetHistoryCount_ = 0;
            offsetHistoryIndex_ = 0;
            lastDriftCalcTimeNs_ = 0;

            if (differentEpoch) {
                std::cout << "[PTPSlave] Master uses a different epoch: "
                          << (baseline / 1000000000LL)
                          << "s from the system clock — normalising it out"
                          << std::endl;
            } else {
                std::cout << "[PTPSlave] Master shares the system clock epoch "
                          << "(initial offset " << offset << "ns)" << std::endl;
            }
        } else {
            const int64_t baseline = epochBaselineNs_.load(std::memory_order_acquire);

            // Compare against the baseline without overflowing: both values are
            // the same magnitude by construction, but a master that restarts its
            // epoch can put them far apart, so difference them as unsigned.
            const uint64_t spread =
                static_cast<uint64_t>(offset) - static_cast<uint64_t>(baseline);
            const int64_t residual = static_cast<int64_t>(spread);

            if (residual > config_.epochThresholdNs ||
                residual < -config_.epochThresholdNs) {
                // The master stepped its clock or restarted. Re-baseline rather
                // than reporting an offset the lock detector can never satisfy.
                epochBaselineNs_.store(offset, std::memory_order_release);
                offsetHistoryCount_ = 0;
                offsetHistoryIndex_ = 0;
                lastDriftCalcTimeNs_ = 0;
                locked_.store(false, std::memory_order_release);
                consecutiveGoodMeasurements_ = 0;

                std::cout << "[PTPSlave] Master epoch changed (jump of "
                          << residual << "ns) — re-baselining" << std::endl;
            }
        }

        const uint64_t normalised = static_cast<uint64_t>(offset) -
                                    static_cast<uint64_t>(epochBaselineNs_.load(std::memory_order_acquire));
        offset = static_cast<int64_t>(normalised);
    }

    // Filter offset (moving average)
    offsetHistory_[offsetHistoryIndex_] = offset;
    offsetHistoryIndex_ = (offsetHistoryIndex_ + 1) % kOffsetFilterSize;
    if (offsetHistoryCount_ < kOffsetFilterSize) offsetHistoryCount_++;

    // Compute filtered offset (average). Sum the deviations from the first
    // sample rather than the samples themselves: with epoch normalisation
    // disabled the raw values can be ~1e18ns, and summing eight of those
    // overflows int64 and flips the sign of the result.
    const int64_t offsetRef = offsetHistory_[0];
    int64_t offsetAcc = 0;
    for (size_t i = 0; i < offsetHistoryCount_; ++i) {
        offsetAcc += offsetHistory_[i] - offsetRef;
    }
    int64_t filteredOffset =
        offsetRef + offsetAcc / static_cast<int64_t>(offsetHistoryCount_);

    // Run the servo on the filtered measurement. What callers see as the
    // offset is the residual the servo has not yet corrected for; with the
    // servo disabled it is the measurement itself, unchanged.
    const int64_t reportedOffset =
        config_.enableServo ? updateServo(filteredOffset) : filteredOffset;

    offsetNs_.store(reportedOffset, std::memory_order_release);

    // Drift estimation. With the servo running, its frequency estimate is
    // already exactly this quantity and is far steadier than differencing two
    // jittery samples, so just publish that.
    if (config_.enableServo) {
        frequencyDriftPpb_.store(servoFreqPpb_.load(std::memory_order_acquire),
                                 std::memory_order_release);
    } else {
        // Measure the interval on the monotonic clock: CLOCK_REALTIME can be
        // stepped by NTP mid-measurement, which would show up as huge drift.
        uint64_t nowNs = getMonotonicTimeNs();
        if (lastDriftCalcTimeNs_ != 0) {
            uint64_t dtNs = nowNs - lastDriftCalcTimeNs_;
            if (dtNs > 500000000ULL) { // Update drift every 500ms minimum
                int64_t dOffset = filteredOffset - lastDriftCalcOffsetNs_;
                // drift in ppb = (dOffset_ns / dt_ns) * 1e9
                double driftPpb = (static_cast<double>(dOffset) / static_cast<double>(dtNs)) * 1e9;

                // Smooth drift
                double prevDrift = frequencyDriftPpb_.load(std::memory_order_acquire);
                double smoothed = prevDrift * 0.9 + driftPpb * 0.1;
                frequencyDriftPpb_.store(smoothed, std::memory_order_release);

                lastDriftCalcTimeNs_ = nowNs;
                lastDriftCalcOffsetNs_ = filteredOffset;
            }
        } else {
            lastDriftCalcTimeNs_ = nowNs;
            lastDriftCalcOffsetNs_ = filteredOffset;
        }
    }

    // Lock detection
    if (std::abs(reportedOffset) < kLockToleranceNs) {
        if (consecutiveGoodMeasurements_ < kLockThreshold * 2) {
            consecutiveGoodMeasurements_++;
        }
    } else {
        consecutiveGoodMeasurements_ = std::max(0, consecutiveGoodMeasurements_ - 1);
    }

    bool wasLocked = locked_.load(std::memory_order_acquire);
    bool nowLocked = consecutiveGoodMeasurements_ >= kLockThreshold;

    if (nowLocked != wasLocked) {
        locked_.store(nowLocked, std::memory_order_release);
        if (nowLocked) {
            std::cout << "[PTPSlave] LOCKED to master — offset="
                      << reportedOffset << "ns delay="
                      << pathDelayNs_.load(std::memory_order_acquire) << "ns" << std::endl;
        } else {
            std::cout << "[PTPSlave] Lock LOST — offset="
                      << reportedOffset << "ns" << std::endl;
        }
    }

    // Invoke callback
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        if (measurementCallback_) {
            PTPMeasurement m;
            m.offsetFromMasterNs = reportedOffset;
            m.meanPathDelayNs = pathDelayNs_.load(std::memory_order_acquire);
            m.frequencyDriftPpb = frequencyDriftPpb_.load(std::memory_order_acquire);
            {
                std::lock_guard<std::mutex> mlock(masterMutex_);
                m.grandmasterID = grandmasterIdentity_;
                m.clockClass = clockClass_.load(std::memory_order_acquire);
                m.clockAccuracy = clockAccuracy_.load(std::memory_order_acquire);
            }
            m.valid = true;
            measurementCallback_(m);
        }
    }
}

// ============================================================================
// Utility
// ============================================================================

uint64_t PTPSlave::getSystemTimeNs() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL +
           static_cast<uint64_t>(ts.tv_nsec);
}

uint64_t PTPSlave::getMonotonicTimeNs() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL +
           static_cast<uint64_t>(ts.tv_nsec);
}

bool PTPSlave::getInterfaceMAC(uint8_t mac[6]) const {
    struct ifaddrs* ifaddrs_ptr = nullptr;
    if (getifaddrs(&ifaddrs_ptr) != 0) return false;

    bool found = false;
    for (struct ifaddrs* ifa = ifaddrs_ptr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family != AF_LINK) continue;
        if (config_.interfaceName != ifa->ifa_name) continue;

        struct sockaddr_dl* sdl = reinterpret_cast<struct sockaddr_dl*>(ifa->ifa_addr);
        if (sdl->sdl_alen == 6) {
            std::memcpy(mac, LLADDR(sdl), 6);
            found = true;
            break;
        }
    }

    freeifaddrs(ifaddrs_ptr);
    return found;
}

} // namespace AES67

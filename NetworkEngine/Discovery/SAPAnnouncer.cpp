//
// SAPAnnouncer.cpp
// AES67 macOS Driver
// Session Announcement Protocol transmitter (RFC 2974)
//

#include "SAPAnnouncer.h"
#include "../NetworkInterfaceDetection.h"
#include "../../Driver/DebugLog.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <atomic>
#include <condition_variable>
#include <cstring>
#include <map>
#include <mutex>
#include <thread>

namespace AES67 {

namespace {

// SAP header, RFC 2974 section 4:
//
//   byte 0: V(3) A(1) R(1) T(1) E(1) C(1)
//   byte 1: authentication length, in 32-bit words
//   bytes 2-3: message identifier hash
//   bytes 4-7: originating source (IPv4)
//
// V=1, A=0 (IPv4 source), R=0, E=0 and C=0 (neither encrypted nor compressed)
// for everything we send. Only T varies: 0 announces a session, 1 deletes it.
constexpr uint8_t kSAPVersionIPv4Announce = 0x20;  // V=1 in bits 5-7
constexpr uint8_t kSAPTypeDeletionBit     = 0x04;

// The payload type is optional per RFC 2974 -- a receiver may infer SDP when
// the payload begins with "v=0" -- but real AES67 gear sends it, so send it
// too rather than relying on every receiver implementing the shortcut.
constexpr const char* kSAPPayloadType = "application/sdp";

/// RFC 2974 requires the message id hash to change whenever the session
/// description changes, and to stay put when it does not; receivers use it to
/// tell a refresh from a modification.
uint16_t hashSDP(const std::string& sdp) {
    // FNV-1a, folded to 16 bits.
    uint32_t hash = 2166136261u;
    for (unsigned char c : sdp) {
        hash ^= c;
        hash *= 16777619u;
    }
    uint16_t folded = static_cast<uint16_t>((hash >> 16) ^ (hash & 0xFFFF));
    return folded == 0 ? 1 : folded;  // 0 is reserved for "no hash"
}

} // namespace

class SAPAnnouncer::Impl {
public:
    ~Impl() { stop(); }

    bool start(const std::string& networkInterface) {
        if (running_.load(std::memory_order_acquire)) {
            return true;
        }

        sockFd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (sockFd_ < 0) {
            AES67_LOGF("SAPAnnouncer: socket() failed (errno=%d: %s)",
                       errno, std::strerror(errno));
            return false;
        }

        // Resolve the interface to an address. On a multi-homed host the
        // routing table will otherwise pick some other network and the
        // announcement never reaches the receivers that need it.
        sourceAddress_ = resolveInterfaceAddress(networkInterface);
        if (!sourceAddress_.empty()) {
            struct in_addr ifAddr {};
            ifAddr.s_addr = ::inet_addr(sourceAddress_.c_str());
            if (::setsockopt(sockFd_, IPPROTO_IP, IP_MULTICAST_IF,
                             &ifAddr, sizeof(ifAddr)) < 0) {
                AES67_LOGF("SAPAnnouncer: IP_MULTICAST_IF failed for %s (errno=%d: %s)",
                           sourceAddress_.c_str(), errno, std::strerror(errno));
                ::close(sockFd_);
                sockFd_ = -1;
                return false;
            }
            AES67_LOGF("SAPAnnouncer: announcing from %s", sourceAddress_.c_str());
        } else {
            AES67_LOG("SAPAnnouncer: no interface address resolved, using default route");
        }

        // Announcements must cross switches to reach other devices, so a TTL
        // of 1 would strand them on this host.
        const int ttl = 32;
        if (::setsockopt(sockFd_, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
            AES67_LOGF("SAPAnnouncer: IP_MULTICAST_TTL failed (errno=%d: %s)",
                       errno, std::strerror(errno));
        }

        std::memset(&destAddr_, 0, sizeof(destAddr_));
        destAddr_.sin_family = AF_INET;
        destAddr_.sin_port = htons(SAPAnnouncer::kSAPPort);
        destAddr_.sin_addr.s_addr = ::inet_addr(SAPAnnouncer::kSAPMulticastAddress);

        running_.store(true, std::memory_order_release);
        announceThread_ = std::thread(&Impl::announceLoop, this);
        AES67_LOG("SAPAnnouncer: started");
        return true;
    }

    void stop() {
        if (!running_.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        // Withdraw everything we advertised before going away, so receivers
        // drop the streams immediately instead of waiting for them to age out.
        sendDeletionsForAllSessions();

        wakeup_.notify_all();
        if (announceThread_.joinable()) {
            announceThread_.join();
        }
        if (sockFd_ >= 0) {
            ::close(sockFd_);
            sockFd_ = -1;
        }
        AES67_LOGF("SAPAnnouncer: stopped after %llu announcement(s)",
                   static_cast<unsigned long long>(announcementsSent_.load()));
    }

    bool isRunning() const { return running_.load(std::memory_order_acquire); }

    void addSession(const StreamID& id, const SDPSession& sdp) {
        std::string payload = buildSDP(sdp);
        {
            std::lock_guard<std::mutex> lock(sessionsMutex_);
            sessions_[id] = payload;
        }
        // Announce straight away so the stream is discoverable now rather than
        // up to one interval from now.
        sendPacket(payload, /*deletion=*/false);
        AES67_LOGF("SAPAnnouncer: announcing session '%s'", sdp.sessionName.c_str());
    }

    void removeSession(const StreamID& id) {
        std::string payload;
        {
            std::lock_guard<std::mutex> lock(sessionsMutex_);
            auto it = sessions_.find(id);
            if (it == sessions_.end()) {
                return;
            }
            payload = it->second;
            sessions_.erase(it);
        }
        sendPacket(payload, /*deletion=*/true);
    }

    void removeAllSessions() {
        sendDeletionsForAllSessions();
        std::lock_guard<std::mutex> lock(sessionsMutex_);
        sessions_.clear();
    }

    size_t getSessionCount() const {
        std::lock_guard<std::mutex> lock(sessionsMutex_);
        return sessions_.size();
    }

    uint64_t getAnnouncementsSent() const {
        return announcementsSent_.load(std::memory_order_acquire);
    }

    void setAnnounceInterval(std::chrono::seconds interval) {
        {
            std::lock_guard<std::mutex> lock(sessionsMutex_);
            announceInterval_ = interval;
        }
        wakeup_.notify_all();
    }

private:
    static std::string resolveInterfaceAddress(const std::string& iface) {
        if (iface.empty()) {
            return {};
        }
        // Accept either a literal address or an interface name.
        struct in_addr probe {};
        if (::inet_pton(AF_INET, iface.c_str(), &probe) == 1) {
            return iface;
        }
        return NetworkInterfaceDetection::getInterfaceIPAddress(iface);
    }

    /// The SDP carried in an announcement describes the session as a receiver
    /// will consume it, so the direction is written from that side. Dante
    /// announces its own transmit flows as "recvonly" and expects the same in
    /// return; announcing "sendonly" describes a stream nobody may subscribe to.
    std::string buildSDP(const SDPSession& sdp) const {
        SDPSession announced = sdp;
        announced.direction = "recvonly";
        if (announced.originAddress.empty()) {
            announced.originAddress = sourceAddress_;
        }
        return SDPParser::generate(announced);
    }

    void announceLoop() {
        while (running_.load(std::memory_order_acquire)) {
            std::chrono::seconds interval;
            std::vector<std::string> payloads;
            {
                std::unique_lock<std::mutex> lock(sessionsMutex_);
                interval = announceInterval_;
                wakeup_.wait_for(lock, interval, [this] {
                    return !running_.load(std::memory_order_acquire);
                });
                if (!running_.load(std::memory_order_acquire)) {
                    return;
                }
                payloads.reserve(sessions_.size());
                for (const auto& entry : sessions_) {
                    payloads.push_back(entry.second);
                }
            }

            for (const auto& payload : payloads) {
                sendPacket(payload, /*deletion=*/false);
            }
        }
    }

    void sendDeletionsForAllSessions() {
        std::vector<std::string> payloads;
        {
            std::lock_guard<std::mutex> lock(sessionsMutex_);
            payloads.reserve(sessions_.size());
            for (const auto& entry : sessions_) {
                payloads.push_back(entry.second);
            }
        }
        for (const auto& payload : payloads) {
            sendPacket(payload, /*deletion=*/true);
        }
    }

    void sendPacket(const std::string& sdp, bool deletion) {
        if (sockFd_ < 0) {
            return;
        }

        std::vector<uint8_t> packet;
        packet.reserve(8 + std::strlen(kSAPPayloadType) + 1 + sdp.size());

        uint8_t flags = kSAPVersionIPv4Announce;
        if (deletion) {
            flags |= kSAPTypeDeletionBit;
        }
        packet.push_back(flags);
        packet.push_back(0);  // no authentication data

        const uint16_t msgIdHash = hashSDP(sdp);
        packet.push_back(static_cast<uint8_t>((msgIdHash >> 8) & 0xFF));
        packet.push_back(static_cast<uint8_t>(msgIdHash & 0xFF));

        // Originating source, in network byte order.
        uint32_t source = 0;
        if (!sourceAddress_.empty()) {
            source = ::inet_addr(sourceAddress_.c_str());  // already network order
        }
        packet.push_back(static_cast<uint8_t>((source) & 0xFF));
        packet.push_back(static_cast<uint8_t>((source >> 8) & 0xFF));
        packet.push_back(static_cast<uint8_t>((source >> 16) & 0xFF));
        packet.push_back(static_cast<uint8_t>((source >> 24) & 0xFF));

        const char* pt = kSAPPayloadType;
        packet.insert(packet.end(), pt, pt + std::strlen(pt));
        packet.push_back(0);  // payload type is NUL terminated

        packet.insert(packet.end(), sdp.begin(), sdp.end());

        ssize_t sent = ::sendto(sockFd_, packet.data(), packet.size(), 0,
                                reinterpret_cast<struct sockaddr*>(&destAddr_),
                                sizeof(destAddr_));
        if (sent < 0) {
            AES67_LOGF("SAPAnnouncer: sendto() failed (errno=%d: %s)",
                       errno, std::strerror(errno));
        } else if (!deletion) {
            announcementsSent_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    int sockFd_{-1};
    struct sockaddr_in destAddr_ {};
    std::string sourceAddress_;

    std::atomic<bool> running_{false};
    std::thread announceThread_;
    std::condition_variable wakeup_;

    mutable std::mutex sessionsMutex_;
    std::map<StreamID, std::string> sessions_;
    std::chrono::seconds announceInterval_{SAPAnnouncer::kDefaultAnnounceInterval};

    std::atomic<uint64_t> announcementsSent_{0};
};

SAPAnnouncer::SAPAnnouncer() : pimpl_(std::make_unique<Impl>()) {}
SAPAnnouncer::~SAPAnnouncer() = default;

bool SAPAnnouncer::start(const std::string& networkInterface) {
    return pimpl_->start(networkInterface);
}
void SAPAnnouncer::stop() { pimpl_->stop(); }
bool SAPAnnouncer::isRunning() const { return pimpl_->isRunning(); }
void SAPAnnouncer::addSession(const StreamID& id, const SDPSession& sdp) {
    pimpl_->addSession(id, sdp);
}
void SAPAnnouncer::removeSession(const StreamID& id) { pimpl_->removeSession(id); }
void SAPAnnouncer::removeAllSessions() { pimpl_->removeAllSessions(); }
size_t SAPAnnouncer::getSessionCount() const { return pimpl_->getSessionCount(); }
uint64_t SAPAnnouncer::getAnnouncementsSent() const { return pimpl_->getAnnouncementsSent(); }
void SAPAnnouncer::setAnnounceInterval(std::chrono::seconds interval) {
    pimpl_->setAnnounceInterval(interval);
}

} // namespace AES67

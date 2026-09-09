//
// SAPAnnouncer.h
// AES67 macOS Driver
// Session Announcement Protocol transmitter (RFC 2974)
//
// Advertises this device's transmit streams on the SAP multicast group so
// that AES67 receivers -- Dante Controller among them -- can discover and
// subscribe to them. Without an announcement a transmit stream is invisible
// to other devices no matter how correct its RTP is, because subscription is
// driven entirely by the announced session description.
//

#ifndef SAP_ANNOUNCER_H
#define SAP_ANNOUNCER_H

#include "../../Shared/Types.h"
#include "../../Driver/SDPParser.h"

#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace AES67 {

class SAPAnnouncer {
public:
    /// Well-known SAP group and port for globally scoped sessions (RFC 2974).
    static constexpr const char* kSAPMulticastAddress = "239.255.255.255";
    static constexpr uint16_t kSAPPort = 9875;

    /// How often each session is re-announced. RFC 2974 derives this from the
    /// announcement bandwidth; AES67 devices in practice settle around 30s,
    /// which is what receivers expect when ageing sessions out.
    static constexpr std::chrono::seconds kDefaultAnnounceInterval{30};

    SAPAnnouncer();
    ~SAPAnnouncer();

    SAPAnnouncer(const SAPAnnouncer&) = delete;
    SAPAnnouncer& operator=(const SAPAnnouncer&) = delete;

    /// Open the announcement socket and begin the announce loop.
    /// @param networkInterface Interface name ("en0") or IP to send from. Empty
    ///                         lets the routing table choose, which is rarely
    ///                         what you want on a multi-homed host.
    bool start(const std::string& networkInterface = "");

    /// Send a deletion for every session, then stop announcing.
    void stop();

    bool isRunning() const;

    /// Begin announcing a session, or replace one already announced under this
    /// id. The first announcement goes out immediately rather than waiting for
    /// the next interval, so a receiver sees the stream as soon as it exists.
    void addSession(const StreamID& id, const SDPSession& sdp);

    /// Send a SAP deletion for the session and stop announcing it.
    void removeSession(const StreamID& id);

    void removeAllSessions();

    size_t getSessionCount() const;

    /// Number of announcement packets sent since start(), for diagnostics.
    uint64_t getAnnouncementsSent() const;

    void setAnnounceInterval(std::chrono::seconds interval);

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace AES67

#endif // SAP_ANNOUNCER_H

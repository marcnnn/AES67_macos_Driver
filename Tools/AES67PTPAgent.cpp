//
// AES67PTPAgent.cpp
// AES67 macOS Driver
//
// Runs the PTP slave outside coreaudiod and publishes grandmaster time for the
// driver to use as its media clock.
//
// The driver cannot run a slave of its own when hosted inside coreaudiod, so
// without this its transmitted RTP timestamps cannot be aligned to the
// grandmaster, and receivers reject the stream as carrying no data. This is a
// background agent rather than part of the SwiftUI app deliberately: the clock
// has to be there whenever audio is running, not only while someone has a
// window open.
//
// Needs no elevated privileges.
//
//   AES67PTPAgent [--interface en0] [--domain 0] [--path /tmp/aes67_ptp_clock]
//

#include "../NetworkEngine/PTP/PTPSlave.h"
#include "../NetworkEngine/PTP/SharedPTPClock.h"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <string>
#include <thread>
#include <chrono>

using namespace AES67;

namespace {
std::atomic<bool> g_running{true};
void onSignal(int) { g_running.store(false); }
}

int main(int argc, char* argv[]) {
    setvbuf(stdout, nullptr, _IONBF, 0);

    std::string interfaceName = "en0";
    std::string clockPath = kSharedPTPClockPath;
    int domain = 0;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--interface" && i + 1 < argc)   interfaceName = argv[++i];
        else if (arg == "--domain" && i + 1 < argc) domain = std::atoi(argv[++i]);
        else if (arg == "--path" && i + 1 < argc)   clockPath = argv[++i];
        else if (arg == "--help" || arg == "-h") {
            printf("AES67 PTP Agent — publishes grandmaster time for the driver\n\n"
                   "Usage: %s [options]\n\n"
                   "  --interface <name>  Interface to run PTP on (default: en0)\n"
                   "  --domain <n>        PTP domain (default: 0)\n"
                   "  --path <file>       Shared clock location (default: %s)\n",
                   argv[0], kSharedPTPClockPath);
            return 0;
        }
    }

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    SharedPTPClockWriter writer;
    if (!writer.open(clockPath)) {
        fprintf(stderr, "AES67PTPAgent: cannot create shared clock at %s: %s\n",
                clockPath.c_str(), strerror(errno));
        return 1;
    }
    printf("AES67PTPAgent: publishing to %s\n", clockPath.c_str());

    PTPSlaveConfig config;
    config.interfaceName = interfaceName;
    config.domain = domain;

    PTPSlave slave(config);
    if (!slave.start()) {
        fprintf(stderr, "AES67PTPAgent: failed to start PTP slave on %s\n",
                interfaceName.c_str());
        return 1;
    }
    printf("AES67PTPAgent: PTP slave running on %s domain %d\n",
           interfaceName.c_str(), domain);

    // Republish faster than a receiver's tolerance for a stale sample, so the
    // driver can always extrapolate from something recent.
    constexpr auto kPublishInterval = std::chrono::milliseconds(200);
    bool wasLocked = false;

    while (g_running.load()) {
        const bool locked = slave.isLocked();
        const uint64_t master = locked ? slave.getMasterTimeNs() : 0;

        writer.publish(master, slave.getServoFrequencyPpb(), locked);

        if (locked != wasLocked) {
            printf("AES67PTPAgent: %s (grandmaster %s)\n",
                   locked ? "LOCKED" : "lock lost",
                   slave.getGrandmasterID().c_str());
            wasLocked = locked;
        }

        std::this_thread::sleep_for(kPublishInterval);
    }

    printf("AES67PTPAgent: stopping\n");
    slave.stop();
    writer.close();
    return 0;
}

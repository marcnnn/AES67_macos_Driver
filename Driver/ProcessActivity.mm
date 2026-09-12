//
// ProcessActivity.mm
// AES67 macOS Driver
//

#include "ProcessActivity.h"
#include "DebugLog.h"

#import <Foundation/Foundation.h>

namespace AES67 {

void BeginLatencyCriticalActivity() {
    static id token = nil;
    if (token != nil) {
        return;
    }

    // NSActivityLatencyCritical is specified as disabling timer coalescing
    // for the process; NSActivityUserInitiated keeps it out of App Nap. The
    // token is deliberately never released -- ending the activity would let
    // the transmit cadence collapse again the moment the device went idle.
    token = [[NSProcessInfo processInfo]
        beginActivityWithOptions:(NSActivityLatencyCritical | NSActivityUserInitiated)
                          reason:@"AES67 RTP transmit runs on a 1ms deadline"];
    [token retain];

    AES67_LOG("ProcessActivity: process declared latency critical");
}

} // namespace AES67

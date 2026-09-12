//
// ProcessActivity.h
// AES67 macOS Driver
// Keep the plug-in's host process out of App Nap and timer coalescing
//
// Requesting deadline scheduling on the transmit thread is not sufficient.
// Thread policy is clamped by the state of the task that owns it: while no
// application has the device open, the process hosting the plug-in is treated
// as idle, its timers are coalesced, and a 1 ms cadence leaves the wire as
// bursts of a dozen packets separated by stalls of 15-35 ms. Setting
// THREAD_LATENCY_QOS_POLICY on the thread does not lift that, because the
// clamp is at task level.
//
// A latency-critical process activity is the documented way to lift it, and
// it has to be held for as long as the process might transmit -- which, since
// transmit streams run whenever they are configured rather than following the
// IO lifecycle, means the life of the plug-in.
//

#pragma once

namespace AES67 {

/// Declare this process latency critical, for its whole lifetime. Idempotent;
/// safe to call from any thread. Costs some power: the process no longer
/// sleeps between packets as far as the scheduler is concerned, which is the
/// point.
void BeginLatencyCriticalActivity();

} // namespace AES67

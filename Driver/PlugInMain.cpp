//
// PlugInMain.cpp
// AES67 macOS Driver - Build #6
// AudioServerPlugIn entry point
//

#include "AES67Device.h"
#include "DebugLog.h"
#include "ProcessActivity.h"
#include <aspl/Plugin.hpp>
#include <aspl/Driver.hpp>
#include <CoreAudio/AudioServerPlugIn.h>
#include <memory>
#include <vector>

namespace AES67 {

//
// AES67 Driver Plugin
//
// This is the main entry point for the AudioServerPlugIn
// macOS Core Audio will load this plugin and create our virtual audio device
//
class AES67Plugin : public aspl::Plugin {
public:
    explicit AES67Plugin(std::shared_ptr<aspl::Context> context)
        : aspl::Plugin(context)
    {
        // One Core Audio device per entry in the config's devices section.
        //
        // Several small devices are not interchangeable with one wide device:
        // ordinary macOS applications always play to the first two channels of
        // whichever device they are pointed at and cannot be told to use
        // channels 3-4, so routing two applications to two different streams
        // needs two devices. loadDevices() never returns empty -- absent a
        // devices section it yields the single default device this driver
        // published before the section existed.
        StreamConfigManager configManager;
        const auto deviceConfigs = configManager.loadDevices();

        AES67_LOGF("AES67Plugin constructor: creating %zu device(s)", deviceConfigs.size());

        for (const auto& deviceConfig : deviceConfigs) {
            auto device = std::make_shared<AES67Device>(context, deviceConfig);

            // Initialize after the shared_ptr exists: InitializeStreams() uses
            // shared_from_this(), which is not valid inside the constructor.
            device->Initialize();

            AddDevice(device);
            ownedDevices_.push_back(device);

            AES67_LOGF("AES67Plugin constructor: registered device '%s' (uid=%s, %u channels)",
                       deviceConfig.name.c_str(), deviceConfig.uid.c_str(),
                       deviceConfig.channelCount);
        }
    }

    std::string GetManufacturer() const override {
        return "AES67 Driver Project";
    }

private:
    // Held so the devices outlive the plug-in registration; aspl::Plugin keeps
    // its own references, this is ownership on our side.
    std::vector<std::shared_ptr<AES67Device>> ownedDevices_;
};

} // namespace AES67

//
// C API Entry Point (Required by AudioServerPlugIn)
//

extern "C" {

// Plugin entry point called by Core Audio
void* Create() {
    AES67_LOG("=== AES67 Driver Create() called ===");

    // Before anything else: transmit pacing depends on this process not being
    // treated as idle. See ProcessActivity.h.
    AES67::BeginLatencyCriticalActivity();

    try {
        AES67_LOG("Step 1: Creating ASPL context...");
        auto context = std::make_shared<aspl::Context>();
        AES67_LOG("Step 1: Context created successfully");

        AES67_LOG("Step 2: Creating AES67Plugin...");
        auto plugin = std::make_shared<AES67::AES67Plugin>(context);
        AES67_LOG("Step 2: Plugin created successfully");

        AES67_LOG("Step 3: Creating Driver wrapper...");
        auto driver = new aspl::Driver(context, plugin);
        AES67_LOG("Step 3: Driver created successfully");

        void* ref = driver->GetReference();
        AES67_LOGF("Step 4: Got driver reference: %p", ref);

        AES67_LOG("=== Create() completed successfully ===");
        return ref;
    }
    catch (const std::exception& e) {
        AES67_LOGF("EXCEPTION in Create(): %s", e.what());
        fprintf(stderr, "AES67 Driver: Failed to create plugin: %s\n", e.what());
        return nullptr;
    }
    catch (...) {
        AES67_LOG("UNKNOWN EXCEPTION in Create()");
        fprintf(stderr, "AES67 Driver: Unknown error during plugin creation\n");
        return nullptr;
    }
}

} // extern "C"

//
// Plugin Factory (Alternative modern C++ API)
//

namespace AES67 {

std::shared_ptr<aspl::Driver> CreateDriver() {
    auto context = std::make_shared<aspl::Context>();
    auto plugin = std::make_shared<AES67Plugin>(context);
    return std::make_shared<aspl::Driver>(context, plugin);
}

} // namespace AES67

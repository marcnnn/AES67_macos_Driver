//
// StreamConfig.h
// AES67 macOS Driver - Build #10
// Stream configuration persistence with JSON serialization
//

#pragma once

#include "../Shared/Types.h"
#include "../Driver/SDPParser.h"
#include "StreamChannelMapper.h"
#include <string>
#include <vector>
#include <optional>
#include <filesystem>

namespace AES67 {

//
// Persisted Stream Configuration
//
// Complete stream configuration including SDP session and channel mapping
// Used for saving/loading stream configurations across driver restarts
//
struct PersistedStreamConfig {
    SDPSession sdp;
    ChannelMapping mapping;

    // Metadata
    bool enabled{true};              // Whether stream is active
    std::string description;         // User-provided description
    uint64_t createdTimestamp{0};    // When stream was added
    uint64_t modifiedTimestamp{0};   // Last modification

    // Jitter buffer configuration: 0 = default (256 slots).
    // Values are clamped to [32, 4096] and rounded up to next power of 2.
    size_t jitterBufferDepth{0};

    // Network interface for multicast binding (e.g., "en0" or "192.168.1.10").
    // Empty string = bind to INADDR_ANY (all interfaces).
    std::string networkInterface;

    // Which Core Audio device this stream belongs to, matching AudioDeviceConfig::uid.
    // Empty means the default device, which is also what every config written
    // before devices existed says -- so those keep loading onto the single
    // device they were written for.
    std::string deviceUID;

    // Validation
    bool isValid() const;
};

//
// Published Core Audio Device
//
// One entry per device the plug-in publishes. Several small devices are not
// the same thing as one device with many channels: ordinary macOS
// applications -- Spotify, browsers, system sounds -- always play to the
// first two channels of whichever device they are pointed at, and cannot be
// told to use channels 3-4. Sending two applications to two different streams
// therefore needs two devices, not one device with four channels.
//
struct AudioDeviceConfig {
    // Shown in System Settings and Audio MIDI Setup.
    std::string name{"AES67 Device"};

    // Must be unique across devices: aspl::Plugin indexes devices by UID, and
    // a duplicate silently replaces the earlier device in that index.
    std::string uid{"com.aes67.driver.device"};

    // Channels advertised to Core Audio, per direction. The ring buffers are
    // always allocated for the maximum; this only limits what the device
    // reports, which is what keeps a 2-channel device from appearing as 128.
    uint32_t channelCount{128};

    // Takes the streams that name no device at all. Set on the first entry, so
    // adding a devices section to an existing config does not silently orphan
    // every stream already in it -- they keep loading, onto the first device.
    bool adoptsUnassignedStreams{false};

    bool isValid() const;
};

//
// Stream Configuration Manager
//
// Handles saving and loading stream configurations to/from disk
// Configurations are stored in JSON format at:
// /Library/Application Support/AES67Driver/streams.json
//
class StreamConfigManager {
public:
    StreamConfigManager();
    ~StreamConfigManager();

    //
    // Configuration File Management
    //

    /// Get the active configuration file path (first found in search order).
    std::string getConfigPath() const;

    /// Set a custom configuration file path (overrides search).
    void setConfigPath(const std::string& path);

    /// Ensure the configuration directory exists.
    bool ensureConfigDirectoryExists();

    /// Get all config search paths in order of priority.
    /// Search order:
    ///   1. AES67_CONFIG_PATH environment variable (if set)
    ///   2. ~/Library/Application Support/AES67Driver/streams.json (user)
    ///   3. /Library/Application Support/AES67Driver/streams.json (system)
    static std::vector<std::string> getConfigSearchPaths();

    /// Find first existing config file from search paths.
    /// @return Path to existing config, or empty string if none found.
    static std::string findExistingConfig();

    //
    // Save/Load Operations
    //

    // Save all stream configurations to file
    bool saveConfig(const std::vector<PersistedStreamConfig>& configs);

    // Load all stream configurations from file
    std::optional<std::vector<PersistedStreamConfig>> loadConfig();

    // Save a single stream configuration (append or update)
    bool saveStream(const PersistedStreamConfig& config);

    // Remove a stream from saved configuration
    bool removeStream(const StreamID& id);

    //
    // JSON Serialization
    //

    // Convert stream configs to JSON string.
    //
    // The devices are written back out with them: auto-save rewrites the whole
    // file, so anything this function omits is destroyed on the first stream
    // change. Callers that have devices must pass them.
    static std::string toJSON(const std::vector<PersistedStreamConfig>& configs,
                              const std::vector<AudioDeviceConfig>& devices = {});

    // Parse stream configs from JSON string
    static std::optional<std::vector<PersistedStreamConfig>> fromJSON(const std::string& json);

    // Read the list of devices to publish.
    //
    // Returns a single default device when the config names none, so a file
    // written before devices existed keeps producing exactly the device it
    // used to. Never returns empty -- a plug-in with no device is useless, and
    // silently publishing nothing is a far worse failure than ignoring a
    // malformed devices section.
    std::vector<AudioDeviceConfig> loadDevices();

    // Parse the devices array out of a config document.
    static std::vector<AudioDeviceConfig> devicesFromJSON(const std::string& json);

    // Convert single config to JSON object string
    static std::string configToJSON(const PersistedStreamConfig& config);

    // Parse single config from JSON object string
    static std::optional<PersistedStreamConfig> configFromJSON(const std::string& json);

    //
    // Helper Functions
    //

    // Create a persisted config from SDP and mapping
    static PersistedStreamConfig createConfig(
        const SDPSession& sdp,
        const ChannelMapping& mapping,
        const std::string& description = ""
    );

    // Get current Unix timestamp (seconds since epoch)
    static uint64_t getCurrentTimestamp();

private:
    std::string configPath_;
    std::string defaultConfigFile_{"streams.json"};

    // Helper methods for JSON serialization
    static std::string escapeJSON(const std::string& str);
    static std::string sdpToJSON(const SDPSession& sdp);
    static std::string mappingToJSON(const ChannelMapping& mapping);

    // Helper methods for JSON deserialization
    static std::optional<SDPSession> sdpFromJSON(const std::string& json);
    static std::optional<ChannelMapping> mappingFromJSON(const std::string& json);

    // Simple JSON parsing helpers
    static std::optional<std::string> extractStringField(const std::string& json, const std::string& field);
    static std::optional<uint64_t> extractUInt64Field(const std::string& json, const std::string& field);
    static std::optional<uint32_t> extractUInt32Field(const std::string& json, const std::string& field);
    static std::optional<uint16_t> extractUInt16Field(const std::string& json, const std::string& field);
    static std::optional<uint8_t> extractUInt8Field(const std::string& json, const std::string& field);
    static std::optional<double> extractDoubleField(const std::string& json, const std::string& field);
    static std::optional<bool> extractBoolField(const std::string& json, const std::string& field);
    static std::optional<int> extractIntField(const std::string& json, const std::string& field);
};

} // namespace AES67

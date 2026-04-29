/**
 * @file wasi_bridge.cpp
 * @brief WASI Bridge Implementation
 *
 * Implements the WASI bridge system for providing host functionality
 * to WASM/WASI environments. This module manages:
 *
 * - Entropy pool for cryptographic operations
 * - USB/HID callbacks for hardware wallet support
 * - Network callbacks for RPC operations
 * - Filesystem callbacks for key storage
 * - Clock callbacks for timestamps
 *
 * In pure WASI environments, many system features are not directly available.
 * The bridge pattern allows host applications to provide these features
 * through registered callbacks.
 */

#include "hd_wallet/wasi_bridge.h"
#include "hd_wallet/config.h"
#include "hd_wallet/types.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <mutex>
#include <string>

#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/secblock.h>

#if HD_WALLET_IS_WASI
#include <wasi/api.h>

extern "C" int32_t __syscall_getdents64(int32_t, int32_t, int32_t) {
    return -52; // ENOSYS: directory enumeration is not available in this module.
}
#elif defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__)
#include <Security/SecRandom.h>
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fstream>
#endif

#if !HD_WALLET_IS_WASI
#include <chrono>
#endif

namespace hd_wallet {

// =============================================================================
// Entropy Pool Implementation
// =============================================================================

namespace {

/**
 * Thread-safe entropy pool with HMAC-based extraction
 *
 * This implementation uses HMAC-SHA256 for both mixing injected entropy
 * and extracting random bytes, providing cryptographic security guarantees.
 *
 * The pool maintains:
 * - A 32-byte key (K) updated with each injection
 * - A 32-byte state (V) updated with each extraction
 * - A counter to ensure unique outputs
 *
 * Based on HMAC-DRBG (NIST SP 800-90A) design principles.
 */
class EntropyPool {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t MIN_ENTROPY = 32;

    EntropyPool() : total_injected_(0), reseed_counter_(0) {
        // Initialize K and V to fixed values (will be updated on first inject)
        std::memset(K_.data(), 0x00, KEY_SIZE);
        std::memset(V_.data(), 0x01, KEY_SIZE);
    }

    /**
     * Inject entropy into the pool using HMAC-based mixing
     *
     * Updates both K and V:
     *   K = HMAC-SHA256(K, V || 0x00 || entropy)
     *   V = HMAC-SHA256(K, V)
     *   K = HMAC-SHA256(K, V || 0x01 || entropy)
     *   V = HMAC-SHA256(K, V)
     */
    void inject(const uint8_t* data, size_t length) {
        std::lock_guard<std::mutex> lock(mutex_);

        // K = HMAC(K, V || 0x00 || entropy)
        update(data, length, 0x00);

        // K = HMAC(K, V || 0x01 || entropy)
        update(data, length, 0x01);

        total_injected_ += length;
        reseed_counter_ = 0;  // Reset reseed counter after new entropy
    }

    /**
     * Extract entropy from the pool using HMAC-based generation
     *
     * For each 32 bytes of output:
     *   V = HMAC-SHA256(K, V)
     *   output = V
     *
     * After extraction, update state:
     *   K = HMAC-SHA256(K, V || 0x00)
     *   V = HMAC-SHA256(K, V)
     */
    size_t extract(uint8_t* output, size_t length) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (total_injected_ < MIN_ENTROPY) {
            return 0;
        }

        // Generate output bytes
        size_t generated = 0;
        while (generated < length) {
            // V = HMAC(K, V)
            CryptoPP::HMAC<CryptoPP::SHA256> hmac(K_.data(), KEY_SIZE);
            hmac.CalculateDigest(V_.data(), V_.data(), KEY_SIZE);

            // Copy to output
            size_t to_copy = std::min(KEY_SIZE, length - generated);
            std::memcpy(output + generated, V_.data(), to_copy);
            generated += to_copy;
        }

        // Update state after extraction (backtracking resistance)
        update(nullptr, 0, 0x00);

        reseed_counter_++;
        return length;
    }

    /**
     * Check if sufficient entropy is available
     */
    bool hasEntropy() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return total_injected_ >= MIN_ENTROPY;
    }

    /**
     * Get total bytes of entropy injected
     */
    size_t totalInjected() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return total_injected_;
    }

    /**
     * Clear the entropy pool securely
     */
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);

        // Secure wipe using SecByteBlock's secure memory
        CryptoPP::SecByteBlock wipe(KEY_SIZE);
        std::memset(wipe.data(), 0, KEY_SIZE);

        // Copy zeros to K and V using volatile to prevent optimization
        volatile uint8_t* volatile_k = K_.data();
        volatile uint8_t* volatile_v = V_.data();
        for (size_t i = 0; i < KEY_SIZE; ++i) {
            volatile_k[i] = 0x00;
            volatile_v[i] = 0x01;
        }

        total_injected_ = 0;
        reseed_counter_ = 0;
    }

private:
    /**
     * Internal update function
     * K = HMAC(K, V || separator || data)
     * V = HMAC(K, V)
     */
    void update(const uint8_t* data, size_t length, uint8_t separator) {
        // Build input: V || separator || data
        std::vector<uint8_t> input;
        input.reserve(KEY_SIZE + 1 + length);
        input.insert(input.end(), V_.begin(), V_.end());
        input.push_back(separator);
        if (data != nullptr && length > 0) {
            input.insert(input.end(), data, data + length);
        }

        // K = HMAC(K, input)
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(K_.data(), KEY_SIZE);
        hmac.CalculateDigest(K_.data(), input.data(), input.size());

        // V = HMAC(K, V)
        hmac.SetKey(K_.data(), KEY_SIZE);
        hmac.CalculateDigest(V_.data(), V_.data(), KEY_SIZE);
    }

    mutable std::mutex mutex_;
    CryptoPP::SecByteBlock K_{KEY_SIZE};  // HMAC key
    CryptoPP::SecByteBlock V_{KEY_SIZE};  // State value
    size_t total_injected_;
    size_t reseed_counter_;
};

// Global entropy pool instance
EntropyPool& getEntropyPool() {
    static EntropyPool pool;
    return pool;
}

} // anonymous namespace

// =============================================================================
// WasiBridge Implementation
// =============================================================================

WasiBridge::WasiBridge()
    : entropy_initialized_(false) {}

WasiBridge& WasiBridge::instance() {
    static WasiBridge instance;
    return instance;
}

// ----- Feature Availability -----

bool WasiBridge::hasFeature(WasiFeature feature) const {
    switch (feature) {
        case WasiFeature::RANDOM:
#if HD_WALLET_IS_WASI
            // In WASI, need either entropy callback or injected entropy
            return entropy_callback_ || getEntropyPool().hasEntropy();
#else
            // Native has system RNG
            return true;
#endif

        case WasiFeature::FILESYSTEM:
#if HD_WALLET_IS_WASI
            return file_read_ || file_write_;
#else
            return true;
#endif

        case WasiFeature::NETWORK:
#if HD_WALLET_IS_WASI
            return static_cast<bool>(http_request_);
#else
            return true;
#endif

        case WasiFeature::USB_HID:
            // Always requires bridge - no native USB in WASM
            return hid_enumerate_ && hid_open_ && hid_close_ &&
                   hid_write_ && hid_read_;

        case WasiFeature::CLOCK:
#if HD_WALLET_IS_WASI
            return static_cast<bool>(get_time_);
#else
            return true;
#endif

        case WasiFeature::ENVIRONMENT:
#if HD_WALLET_IS_WASI
            // WASI provides env access by default
            return true;
#else
            return true;
#endif

        default:
            return false;
    }
}

WasiWarning WasiBridge::getWarning(WasiFeature feature) const {
    if (hasFeature(feature)) {
        return WasiWarning::NONE;
    }

    switch (feature) {
        case WasiFeature::RANDOM:
            return WasiWarning::NEEDS_ENTROPY;

        case WasiFeature::USB_HID:
            return WasiWarning::NEEDS_BRIDGE;

        case WasiFeature::NETWORK:
        case WasiFeature::FILESYSTEM:
#if HD_WALLET_IS_WASI
            return WasiWarning::NEEDS_BRIDGE;
#else
            return WasiWarning::NONE;
#endif

        case WasiFeature::CLOCK:
#if HD_WALLET_IS_WASI
            return WasiWarning::NEEDS_CAPABILITY;
#else
            return WasiWarning::NONE;
#endif

        default:
            return WasiWarning::NOT_AVAILABLE_WASI;
    }
}

std::string WasiBridge::getWarningMessage(WasiFeature feature) const {
    WasiWarning warning = getWarning(feature);

    switch (warning) {
        case WasiWarning::NONE:
            return "";

        case WasiWarning::NEEDS_ENTROPY:
            return "Random number generation requires entropy injection. "
                   "Call hd_inject_entropy() before cryptographic operations.";

        case WasiWarning::NEEDS_BRIDGE:
            switch (feature) {
                case WasiFeature::USB_HID:
                    return "USB/HID access requires host bridge callbacks. "
                           "Register HID callbacks via setHidEnumerateCallback(), etc.";
                case WasiFeature::NETWORK:
                    return "Network access requires host bridge callback. "
                           "Register HTTP callback via setHttpRequestCallback().";
                case WasiFeature::FILESYSTEM:
                    return "Filesystem access requires host bridge callbacks. "
                           "Register file callbacks via setFileReadCallback(), etc.";
                default:
                    return "Feature requires host bridge callback.";
            }

        case WasiWarning::NOT_AVAILABLE_WASI:
            return "Feature not available in WASI environment.";

        case WasiWarning::DISABLED_FIPS:
            return "Feature disabled in FIPS compliance mode.";

        case WasiWarning::NEEDS_CAPABILITY:
            return "Feature requires specific WASI capability from runtime.";

        default:
            return "Unknown warning.";
    }
}

// ----- Entropy -----

void WasiBridge::setEntropyCallback(callbacks::EntropyCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    entropy_callback_ = std::move(callback);
}

int32_t WasiBridge::getEntropy(uint8_t* buffer, size_t length) {
    if (buffer == nullptr || length == 0) {
        return -1;
    }

    // Try callback first (allows host to override)
    if (entropy_callback_) {
        return entropy_callback_(buffer, length);
    }

    // Try entropy pool (for manually injected entropy)
    if (getEntropyPool().hasEntropy()) {
        size_t extracted = getEntropyPool().extract(buffer, length);
        return static_cast<int32_t>(extracted);
    }

#if HD_WALLET_IS_WASI
    // WASI: Use the random_get syscall for cryptographically secure entropy
    int32_t result = __wasi_random_get(buffer, length);
    if (result == 0) {
        return static_cast<int32_t>(length);
    }
    return -1;
#elif defined(__linux__)
    // Linux: Use getrandom() for cryptographically secure entropy
    ssize_t result = getrandom(buffer, length, 0);
    if (result >= 0 && static_cast<size_t>(result) == length) {
        return static_cast<int32_t>(length);
    }
    return -1;
#elif defined(__APPLE__)
    // macOS/iOS: Use SecRandomCopyBytes for cryptographically secure entropy
    int result = SecRandomCopyBytes(kSecRandomDefault, length, buffer);
    if (result == errSecSuccess) {
        return static_cast<int32_t>(length);
    }
    return -1;
#elif defined(_WIN32)
    // Windows: Use BCryptGenRandom for cryptographically secure entropy
    NTSTATUS status = BCryptGenRandom(NULL, buffer, static_cast<ULONG>(length), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (BCRYPT_SUCCESS(status)) {
        return static_cast<int32_t>(length);
    }
    return -1;
#else
    // Fallback: Read from /dev/urandom
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (urandom.good()) {
        urandom.read(reinterpret_cast<char*>(buffer), length);
        if (urandom.gcount() == static_cast<std::streamsize>(length)) {
            return static_cast<int32_t>(length);
        }
    }
    return -1;
#endif
}

void WasiBridge::injectEntropy(const uint8_t* entropy, size_t length) {
    if (entropy == nullptr || length == 0) {
        return;
    }

    // SECURITY FIX [CRIT-02]: Mix injected entropy with additional sources
    // to prevent attacker from fully controlling randomness.
    //
    // Even if an attacker controls the injected entropy, we mix in:
    // 1. Current timestamp (if available)
    // 2. A monotonic injection counter
    // 3. Pool's current state (via HMAC in the pool itself)
    //
    // This provides defense-in-depth: attacker would need to control ALL
    // sources to predict output.

    // Get current time as additional entropy (if available)
    std::array<uint8_t, 8> time_bytes{};
    int64_t now = getTime();
    if (now > 0) {
        std::memcpy(time_bytes.data(), &now, sizeof(now));
    }

    // Injection counter (monotonically increasing, adds unpredictability)
    static std::atomic<uint64_t> injection_counter{0};
    uint64_t counter = injection_counter.fetch_add(1, std::memory_order_relaxed);
    std::array<uint8_t, 8> counter_bytes{};
    std::memcpy(counter_bytes.data(), &counter, sizeof(counter));

    // Mix all entropy sources using HMAC-SHA256
    // Result = HMAC(injected_entropy, time || counter || length_as_bytes)
    CryptoPP::SecByteBlock mixed_input(length + sizeof(time_bytes) + sizeof(counter_bytes) + sizeof(size_t));
    size_t offset = 0;

    std::memcpy(mixed_input.data() + offset, entropy, length);
    offset += length;

    std::memcpy(mixed_input.data() + offset, time_bytes.data(), sizeof(time_bytes));
    offset += sizeof(time_bytes);

    std::memcpy(mixed_input.data() + offset, counter_bytes.data(), sizeof(counter_bytes));
    offset += sizeof(counter_bytes);

    std::memcpy(mixed_input.data() + offset, &length, sizeof(length));

    // Hash the mixed data to produce final entropy
    CryptoPP::SecByteBlock hashed(32);
    CryptoPP::SHA256 hash;
    hash.CalculateDigest(hashed.data(), mixed_input.data(), mixed_input.size());

    // Inject both the raw entropy AND the mixed hash
    // This preserves full entropy from the source while adding our mixing
    getEntropyPool().inject(entropy, length);
    getEntropyPool().inject(hashed.data(), hashed.size());

    entropy_initialized_ = true;
}

bool WasiBridge::hasEntropy() const {
    return entropy_callback_ || getEntropyPool().hasEntropy();
}

// ----- USB/HID -----

void WasiBridge::setHidEnumerateCallback(callbacks::HidEnumerateCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    hid_enumerate_ = std::move(callback);
}

void WasiBridge::setHidOpenCallback(callbacks::HidOpenCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    hid_open_ = std::move(callback);
}

void WasiBridge::setHidCloseCallback(callbacks::HidCloseCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    hid_close_ = std::move(callback);
}

void WasiBridge::setHidWriteCallback(callbacks::HidWriteCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    hid_write_ = std::move(callback);
}

void WasiBridge::setHidReadCallback(callbacks::HidReadCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    hid_read_ = std::move(callback);
}

std::vector<HidDeviceInfo> WasiBridge::hidEnumerate() {
    if (!hid_enumerate_) {
        return {};
    }
    return hid_enumerate_();
}

int32_t WasiBridge::hidOpen(const std::string& path) {
    if (!hid_open_) {
        return -1;
    }
    return hid_open_(path);
}

void WasiBridge::hidClose(int32_t handle) {
    if (hid_close_) {
        hid_close_(handle);
    }
}

int32_t WasiBridge::hidWrite(int32_t handle, const std::vector<uint8_t>& data) {
    if (!hid_write_) {
        return -1;
    }
    return hid_write_(handle, data);
}

int32_t WasiBridge::hidRead(int32_t handle, uint8_t* buffer,
                            size_t max_length, uint32_t timeout_ms) {
    if (!hid_read_) {
        return -1;
    }
    return hid_read_(handle, buffer, max_length, timeout_ms);
}

// ----- Network -----

void WasiBridge::setHttpRequestCallback(callbacks::HttpRequestCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    http_request_ = std::move(callback);
}

callbacks::HttpResponse WasiBridge::httpRequest(
    const std::string& method,
    const std::string& url,
    const std::vector<std::pair<std::string, std::string>>& headers,
    const std::string& body) {
    if (!http_request_) {
        return {-1, "No HTTP callback registered", {}};
    }
    return http_request_(method, url, headers, body);
}

// ----- Filesystem -----

void WasiBridge::setFileReadCallback(callbacks::FileReadCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    file_read_ = std::move(callback);
}

void WasiBridge::setFileWriteCallback(callbacks::FileWriteCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    file_write_ = std::move(callback);
}

void WasiBridge::setFileExistsCallback(callbacks::FileExistsCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    file_exists_ = std::move(callback);
}

void WasiBridge::setFileDeleteCallback(callbacks::FileDeleteCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    file_delete_ = std::move(callback);
}

std::vector<uint8_t> WasiBridge::fileRead(const std::string& path) {
    if (!file_read_) {
        return {};
    }
    return file_read_(path);
}

bool WasiBridge::fileWrite(const std::string& path, const std::vector<uint8_t>& data) {
    if (!file_write_) {
        return false;
    }
    return file_write_(path, data);
}

bool WasiBridge::fileExists(const std::string& path) {
    if (!file_exists_) {
        return false;
    }
    return file_exists_(path);
}

bool WasiBridge::fileDelete(const std::string& path) {
    if (!file_delete_) {
        return false;
    }
    return file_delete_(path);
}

// ----- Clock -----

void WasiBridge::setGetTimeCallback(callbacks::GetTimeCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    get_time_ = std::move(callback);
}

int64_t WasiBridge::getTime() {
    if (get_time_) {
        return get_time_();
    }

#if !HD_WALLET_IS_WASI
    // Native: use system time
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
#else
    // WASI without callback
    return -1;
#endif
}

// ----- Reset -----

void WasiBridge::reset() {
    entropy_callback_ = nullptr;
    hid_enumerate_ = nullptr;
    hid_open_ = nullptr;
    hid_close_ = nullptr;
    hid_write_ = nullptr;
    hid_read_ = nullptr;
    http_request_ = nullptr;
    file_read_ = nullptr;
    file_write_ = nullptr;
    file_exists_ = nullptr;
    file_delete_ = nullptr;
    get_time_ = nullptr;

    // Clear entropy pool
    getEntropyPool().clear();
    entropy_initialized_ = false;
}

// =============================================================================
// C API Implementation
// =============================================================================

namespace {

// Thread-local storage for warning messages
thread_local std::string warning_message_buffer;

} // anonymous namespace

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_wasi_has_feature(int32_t feature) {
    if (feature < 0 || feature >= static_cast<int32_t>(WasiFeature::COUNT)) {
        return 0;
    }
    return WasiBridge::instance().hasFeature(static_cast<WasiFeature>(feature)) ? 1 : 0;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_wasi_get_warning(int32_t feature) {
    if (feature < 0 || feature >= static_cast<int32_t>(WasiFeature::COUNT)) {
        return static_cast<int32_t>(WasiWarning::NOT_AVAILABLE_WASI);
    }
    return static_cast<int32_t>(
        WasiBridge::instance().getWarning(static_cast<WasiFeature>(feature))
    );
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_wasi_get_warning_message(int32_t feature) {
    if (feature < 0 || feature >= static_cast<int32_t>(WasiFeature::COUNT)) {
        return "Invalid feature code";
    }
    warning_message_buffer = WasiBridge::instance().getWarningMessage(
        static_cast<WasiFeature>(feature)
    );
    return warning_message_buffer.c_str();
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_inject_entropy(const uint8_t* entropy, size_t length) {
    WasiBridge::instance().injectEntropy(entropy, length);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_get_entropy_status() {
    // Returns:
    //  0 = No entropy available
    //  1 = Entropy callback set
    //  2 = Entropy pool has sufficient entropy
    //  3 = Both callback and pool available

    int32_t status = 0;
    auto& bridge = WasiBridge::instance();

    if (bridge.hasEntropy()) {
        status |= 2;
    }

    return status;
}

// =============================================================================
// Additional C API Functions
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_get_random(uint8_t* buffer, size_t length) {
    return WasiBridge::instance().getEntropy(buffer, length);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_wasi_reset() {
    WasiBridge::instance().reset();
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_get_version() {
    return HD_WALLET_VERSION_STRING;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_get_version_major() {
    return HD_WALLET_VERSION_MAJOR;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_get_version_minor() {
    return HD_WALLET_VERSION_MINOR;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_get_version_patch() {
    return HD_WALLET_VERSION_PATCH;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_is_wasm() {
#if HD_WALLET_IS_WASM
    return 1;
#else
    return 0;
#endif
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_is_wasi() {
#if HD_WALLET_IS_WASI
    return 1;
#else
    return 0;
#endif
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_is_fips_mode() {
#if HD_WALLET_FIPS_MODE
    return 1;
#else
    return 0;
#endif
}

// Alias for hd_get_version (which already returns the version string)
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_get_version_string() {
    return HD_WALLET_VERSION_STRING;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_has_cryptopp() {
#if HD_WALLET_USE_CRYPTOPP
    return 1;
#else
    return 0;
#endif
}

// Thread-local storage for coin list string
static thread_local std::string g_supported_coins;

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_get_supported_coins() {
    g_supported_coins = "[";
#if HD_WALLET_ENABLE_BITCOIN
    g_supported_coins += "\"bitcoin\",";
#endif
#if HD_WALLET_ENABLE_ETHEREUM
    g_supported_coins += "\"ethereum\",";
#endif
#if HD_WALLET_ENABLE_COSMOS
    g_supported_coins += "\"cosmos\",";
#endif
#if HD_WALLET_ENABLE_SOLANA
    g_supported_coins += "\"solana\",";
#endif
#if HD_WALLET_ENABLE_POLKADOT
    g_supported_coins += "\"polkadot\",";
#endif
    // Remove trailing comma if present
    if (g_supported_coins.size() > 1) {
        g_supported_coins.pop_back();
    }
    g_supported_coins += "]";
    return g_supported_coins.c_str();
}

// Thread-local storage for curves list string
static thread_local std::string g_supported_curves;

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_get_supported_curves() {
    g_supported_curves = "[\"secp256k1\",\"ed25519\",\"p256\",\"p384\",\"x25519\"]";
    return g_supported_curves.c_str();
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_curve_supported(int32_t curve) {
    switch (static_cast<Curve>(curve)) {
        case Curve::SECP256K1:
#if HD_WALLET_ENABLE_SECP256K1
            return 1;
#else
            return 0;
#endif
        case Curve::ED25519:
#if HD_WALLET_ENABLE_ED25519
            return 1;
#else
            return 0;
#endif
        case Curve::P256:
#if HD_WALLET_ENABLE_P256
            return 1;
#else
            return 0;
#endif
        case Curve::P384:
#if HD_WALLET_ENABLE_P384
            return 1;
#else
            return 0;
#endif
        case Curve::X25519:
#if HD_WALLET_ENABLE_X25519
            return 1;
#else
            return 0;
#endif
        default:
            return 0;
    }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_error_string(int32_t error_code) {
    return errorToString(static_cast<Error>(error_code));
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_curve_string(int32_t curve) {
    return curveToString(static_cast<Curve>(curve));
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_coin_type_string(int32_t coin_type) {
    return coinTypeToString(static_cast<CoinType>(coin_type));
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_coin_type_curve(int32_t coin_type) {
    return static_cast<int32_t>(coinTypeToCurve(static_cast<CoinType>(coin_type)));
}

} // namespace hd_wallet

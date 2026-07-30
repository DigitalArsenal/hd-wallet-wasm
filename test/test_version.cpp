#include "test_framework.h"

#include <cstdint>

extern "C" {
const char* hd_get_version_string();
int32_t hd_get_version_major();
int32_t hd_get_version_minor();
int32_t hd_get_version_patch();
}

TEST_CASE(VersionContract, VersionMacrosMatchRelease) {
    ASSERT_EQ(2, HD_WALLET_VERSION_MAJOR);
    ASSERT_EQ(0, HD_WALLET_VERSION_MINOR);
    ASSERT_EQ(29, HD_WALLET_VERSION_PATCH);
    ASSERT_STR_EQ("2.0.30", HD_WALLET_VERSION_STRING);
}

TEST_CASE(VersionContract, RuntimeVersionStringMatchesRelease) {
    ASSERT_STR_EQ("2.0.30", hd_get_version_string());
}

TEST_CASE(VersionContract, RuntimeVersionIntegerMatchesRelease) {
    const int runtimeVersion = hd_get_version_major() * 10000 +
                               hd_get_version_minor() * 100 +
                               hd_get_version_patch();
    const int expectedVersion = HD_WALLET_VERSION_MAJOR * 10000 +
                                HD_WALLET_VERSION_MINOR * 100 +
                                HD_WALLET_VERSION_PATCH;
    ASSERT_EQ(expectedVersion, runtimeVersion);
}

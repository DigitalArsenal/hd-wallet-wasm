#include "test_framework.h"

#include <cstdint>

extern "C" {
const char* hd_get_version_string();
int32_t hd_get_version_major();
int32_t hd_get_version_minor();
int32_t hd_get_version_patch();
}

TEST_CASE(VersionContract, VersionMacrosAre_2_0_22) {
    ASSERT_EQ(2, HD_WALLET_VERSION_MAJOR);
    ASSERT_EQ(0, HD_WALLET_VERSION_MINOR);
    ASSERT_EQ(22, HD_WALLET_VERSION_PATCH);
    ASSERT_STR_EQ("2.0.22", HD_WALLET_VERSION_STRING);
}

TEST_CASE(VersionContract, RuntimeVersionStringIs_2_0_22) {
    ASSERT_STR_EQ("2.0.22", hd_get_version_string());
}

TEST_CASE(VersionContract, RuntimeVersionIntegerIs_20022) {
    const int runtimeVersion = hd_get_version_major() * 10000 +
                               hd_get_version_minor() * 100 +
                               hd_get_version_patch();
    ASSERT_EQ(20022, runtimeVersion);
}

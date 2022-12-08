#include <gtest/gtest.h>

#include "netguard.h"
#include "util.h"

TEST(TestUtil, ValidUTF8) {
    // 1) Valid UTF8
    EXPECT_TRUE(is_valid_utf8("mapi.speedtest.net"));

    // 2) Invalid UTF8
    EXPECT_FALSE(is_valid_utf8("AB\xfc"));
}

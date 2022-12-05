#include <gtest/gtest.h>

#include "netguard.h"
#include "util.h"

TEST(TestTCP, SendSynReceiveSynAck) {
printf("Running test");
//EXPECT_TRUE(is_valid_utf8("hello world"));
const int s = 1;
printf("test: %s", strstate(s));
printf("Done");
}

// TODO: compiling with Gtest needs CPP --> need to change all files. Compiler is stricter. GOod errors to fix anyway
// Try with AntMon first? Less JNI to deal with
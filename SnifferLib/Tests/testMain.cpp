#include "gtest/gtest.h"
#include "parser.h"

size_t BeforeRun_sizePacketsInfo = 1;
size_t BeforeRun_sizeParsedPacketVec = 2;

class ParserTest : public testing::Test
{
    
public:
    static void SetUpTestSuite() 
    {
        pars::Parser parser("input.pcap");
        BeforeRun_sizePacketsInfo = parser.sizePacketsInfo();
        BeforeRun_sizeParsedPacketVec = parser.sizeParsedPacketVec();
        parser.run();
    }

    static void TearDownTestSuite()
    {
        // parser.~parser();
    }

};

// Demonstrate some basic assertions.
// TEST(HelloTest, BasicAssertions)
// {
//   // Expect two strings not to be equal.
//   EXPECT_STRNE("hello", "world");
//   // Expect equality.
//   EXPECT_EQ(7 * 6, 42);
// }

TEST(ParserTest, sizeOf)
{
    ParserTest::SetUpTestSuite();
    // // Arrage
    // pars::Parser parser("input.pcap");
    // size_t BeforeSizeRawVec = parser.sizePacketsInfo();
    // size_t BeforeSizeParsedPacketVec = parser.sizeParsedPacketVec();
    // parser.run();

    // // Act
    // size_t sizeRawVec = parser.sizePacketsInfo();
    // size_t sizeParsedPacketVec = parser.sizeParsedPacketVec();

    // // Assert
    EXPECT_EQ(BeforeRun_sizePacketsInfo, BeforeRun_sizeParsedPacketVec);
    // EXPECT_EQ(sizeRawVec, sizeParsedPacketVec);
}

int main(int argc, char **argv)
{
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
#include "gtest/gtest.h"
#include "parser.h"

// size_t BeforeRun_sizePacketsInfo = 1;
// size_t BeforeRun_sizeParsedPacketVec = 2;

class ParserFixture : public testing::Test
{
public:
    // pars::Parser* ptrParser;
    pars::Parser parser;

    // ParserFixture() : ptrParser(new pars::Parser("input.pcap")) { }
    ParserFixture() : parser("input.pcap") {}
    static void SetUpTestSuite()
    {
        // ptrParser = new pars::Parser("input.pcap");
    }

    static void TearDownTestSuite()
    {
    }

    void SetUp()
    {
        // ptrParser = new pars::Parser("input.pcap");
        // parser = pars::Parser("input.pcap");
        //  BeforeRun_sizePacketsInfo = parser.sizePacketsInfo();
        //  BeforeRun_sizeParsedPacketVec = parser.sizeParsedPacketVec();
        // parser.run();
    }

    void TearDown()
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

TEST_F(ParserFixture, sizeOf)
{
    // ParserTest::SetUpTestSuite();
    //  // Arrage
    //  pars::Parser parser("input.pcap");
    //  size_t BeforeSizeRawVec = parser.sizePacketsInfo();
    //  size_t BeforeSizeParsedPacketVec = parser.sizeParsedPacketVec();
    //  parser.run();

    // // Act
    // size_t sizeRawVec = parser.sizePacketsInfo();
    // size_t sizeParsedPacketVec = parser.sizeParsedPacketVec();

    // // Assert
    // EXPECT_EQ(ptrParser->sizePacketsInfo(), 0);
    EXPECT_EQ(parser.sizePacketsInfo(), 0);

    // EXPECT_EQ(sizeRawVec, sizeParsedPacketVec);
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
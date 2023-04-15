#include "gtest/gtest.h"
#include "parser.h"

class ParserFixture : public testing::Test
{
public:
    pars::Parser *ptrParser;

    static void SetUpTestSuite()
    {
        std::cout << ">>SetUpTestSuite" << std::endl;
    }

    static void TearDownTestSuite()
    {
        std::cout << ">>TearDownTestSuite" << std::endl;
    }

    void SetUp()
    {
        std::cout << ">>SetUp" << std::endl;

        ptrParser = new pars::Parser("input.pcap");
    }

    void TearDown()
    {
        std::cout << ">>TearDown" << std::endl;

        delete ptrParser;
    }
};

TEST(SomeSuite, checkThrow)
{
    // Arrage is empty for this case test

    // Assert
    //std::cout << "EXPECT_THROW #1:" << std::endl;
    EXPECT_THROW(pars::Parser ob("in"), std::runtime_error);
    std::cout << "EXPECT_THROW #1 - DONE" << std::endl;

    //std::cout << "EXPECT_THROW #2:" << std::endl;
    EXPECT_THROW(pars::Parser ob("in"), spdlog::spdlog_ex);
    std::cout << "EXPECT_THROW #2 - DONE" << std::endl;

    //std::cout << "EXPECT_THROW #3:" << std::endl;
    EXPECT_THROW(pars::Parser ob("eth1001", 15, "full"), std::runtime_error);
    std::cout << "EXPECT_THROW #3 - DONE" << std::endl;
}

TEST_F(ParserFixture, sizeOf)
{
    // Arrage is empty for this test case

    // Act:
    size_t beforeParsingPacketsInfo = ptrParser->sizePacketsInfo();
    size_t beforeParsingParsedPacketVec = ptrParser->sizeParsedPacketVec();
    ptrParser->run();
    size_t afterParsingPacketsInfo = ptrParser->sizePacketsInfo();
    size_t afterParsingParsedPacketVec = ptrParser->sizeParsedPacketVec();

    // Assert:
    //std::cout << "EXPECT_EQ #1:" << std::endl;
    EXPECT_EQ(beforeParsingPacketsInfo, 0);
    std::cout << "EXPECT_EQ #1 - DONE" << std::endl;

    //std::cout << "EXPECT_EQ #2:" << std::endl;
    EXPECT_EQ(beforeParsingParsedPacketVec, 0);
    std::cout << "EXPECT_EQ #2 - DONE" << std::endl;

    //std::cout << "EXPECT_EQ #3:" << std::endl;
    EXPECT_EQ(afterParsingPacketsInfo, afterParsingParsedPacketVec);
    std::cout << "EXPECT_EQ #3 - DONE" << std::endl;

    //std::cout << "EXPECT_GE #1:" << std::endl;
    EXPECT_GE(afterParsingPacketsInfo, 1);
    std::cout << "EXPECT_GE #1 - DONE" << std::endl;

    //std::cout << "EXPECT_GE #2:" << std::endl;
    EXPECT_GE(afterParsingParsedPacketVec, 1);
    std::cout << "EXPECT_GE #2 - DONE" << std::endl;
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
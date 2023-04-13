// #pragma once
#include <iostream>
#include <map>
#include <exception>

#include "packetStats.h" //mine class for statistics of protocols

#include "PcapLiveDeviceList.h" //representing network interface (PcapLiveDevice for Linux)
#include "stdlib.h"
#include "SystemUtils.h"    //several useful utilities for interaction with OS
#include "PcapFileDevice.h" //API for reader file

// for Parsing Protocols:
#include <EthLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <DnsLayer.h>
#include <HttpLayer.h>

// for logger:
#include "spdlog/spdlog.h"
#include "spdlog/async.h" //support for async logging.
#include "spdlog/sinks/basic_file_sink.h"

namespace pars
{
    using timeout = unsigned long long;
    using vecStr = std::vector<std::string>;
    using vvStr = std::vector<vecStr>;
    using PacketVector = std::vector<pcpp::Packet>;

    class Parser
    {
    private:
        pcpp::PcapLiveDevice *device; // network interface
        pcpp::IFileReaderDevice *reader; //API for read file

        pars::timeout timeCapture; // time to capture RawPackets
        std::string workMode;      // working mode of Parser (brief, full or protei mode)

        pcpp::RawPacketVector rawVec;       // RawPackets' vector
        pars::PacketVector parsedPacketVec; // already parsed Packets' vector
        pars::stats::PacketStats stats;     // to get statistics about Packets
        pars::vvStr packetsInfo;            // lines with full extracted data from each protocols

        std::map<std::string, int> countUrl;    // to count URL from HTTP (for 'protei' working mode)
        std::shared_ptr<spdlog::logger> logger; // asynchronous logger


        // main parsing functions of the bottom:
        std::string getInfoProtocol(pcpp::Layer *curLayer);

        std::string reassemblyEth(pcpp::EthLayer *ethLayer);
        std::string reassemblyIPv4(pcpp::IPv4Layer *ipLayer);
        std::string IPv4OptionTypeToString(pcpp::IPv4OptionTypes type);
        std::string reassemblyIPv6(pcpp::IPv6Layer *ipLayer);
        std::string reassemblyTcp(pcpp::TcpLayer *tcpLayer);
        std::string TcpOptionTypeToString(pcpp::TcpOptionType type);
        std::string reassemblyUdp(pcpp::UdpLayer *udpLayer);
        std::string reassemblyDns(pcpp::DnsLayer *dnsLayer);
        std::string DnsTypeToString(pcpp::DnsResourceType type);
        std::string reassemblyHttpRequest(pcpp::HttpRequestLayer *httpReqLayer);
        std::string printHttpMethod(pcpp::HttpRequestLayer::HttpMethod httpMethod);
        std::string reassemblyHttpResponse(pcpp::HttpResponseLayer *httpResLayer);
        std::string printHttpVersion(pcpp::HttpVersion version);

        void startSniff(); // capture bits of raw packets via interface
        void startRead();  // reade file .pcap

        // Work mode (brief, full or protei mode):
        void briefInfo();
        void fullInfo();
        void specialTaskInfo(); // it is protei mode to count the URL from HTTP

    public:
        Parser(std::string interfaceName, timeout timeCapture, std::string workMode);
        Parser(std::string fileName);

        void run(); // main method for start work the Parser (read file or capture)

        size_t sizePacketsInfo() { return packetsInfo.size(); }
        size_t sizeParsedPacketVec() { return parsedPacketVec.size(); }

        ~Parser();
    };

}
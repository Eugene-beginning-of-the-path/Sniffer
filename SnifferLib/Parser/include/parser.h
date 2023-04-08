// #pragma once
#include <iostream>
#include <map>
#include <exception>
#include "PcapLiveDeviceList.h" //representing network interface (PcapLiveDevice for Linux)
#include "stdlib.h"
#include "SystemUtils.h" //several useful utilities for interaction with OS
#include "packetStats.h" //mine class for statistics of protocols

#include <EthLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <DnsLayer.h>
#include <HttpLayer.h>

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
        pcpp::RawPacketVector rawVec; // RawPackets' vector
        pars::timeout timeCapture;    // time to capture RawPackets

        pars::PacketVector parsedPacketVec; // already parsed Packets' vector
        pars::stats::PacketStats stats;     // to get statistics about Packets
        pars::vvStr packetsInfo;            // lines with full extracted data from each protocols

        std::map<std::string, int> countUrl;
        std::string workMode;
        std::shared_ptr<spdlog::logger> logger;

        void briefInfoPackets();
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

        // Work mode:
        void briefInfo();
        void fullInfo();
        void specialTaskInfo();

    public:
        Parser(std::string interfaceName, timeout timeCapture, std::string workMode);

        void startSniff();
    };

    // std::string

}
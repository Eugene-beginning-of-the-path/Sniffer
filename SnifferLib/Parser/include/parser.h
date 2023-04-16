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

/// @file

/**
 * \namespace pars
 * \brief The main namespace for the SnifferLib
 */
namespace pars
{
    using timeout = unsigned long long;
    using vecStr = std::vector<std::string>;
    using vvStr = std::vector<vecStr>;
    using PacketVector = std::vector<pcpp::Packet>;

    /**
	 * @class Parser
	 * \brief The main class, which can analyze raw packets, read .pcap file and analyze raw packets from it
     * \details This class can listen to the network interface for a specified time and provide you with 
     *  information in one of three modes('brief', 'full' or 'protei'). Also this class can read .pcap files 
     *  containing raw packets, in which case it will analyze them and provide you with a detailed summary of 
     *  information about each packets and the protocol of this packet. Logs are recorded from creation to 
     *  destruction of an object of this class.
	 */
    class Parser
    {
    private:
 
        pcpp::PcapLiveDevice *device;    //API for the network interface
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
        /**
        @brief The constructor for preparing to capture raw packets via a network interface
        @param[in] interfaceName The name of network interface you want to listen to
        @param[in] timeCapture The time in seconds during wich you want to listen to your network interface
        @param[in] workMode You can specify one of the working mode for this analyzer (brief, full or protei).
        Working mode 'brief' will display you the number of protocols from the captured packets.
        Working mode 'full' in addition to number of protocols from captured packets, it will also display 
        information from the headers of these protocols.
        Working mode 'protei' does the same things as the previously working modes, but also display the 
        numbers of URL at the end.
        @throw spdlog::spdlog_ex If Logger has an initialization failed
        @throw std::runtime_error If the interface with the name <interfaceName> could not be found. 
        If the network interface could not be opened.
        */
        Parser(std::string interfaceName, timeout timeCapture, std::string workMode);

        /**
        @brief The constructor for preparing to read .pcap file, and analysis raw packets from it.
        @param[in] fileName The name of the file with .pcap format to then read it and analize raw packets 
        from it
        @throw spdlog::spdlog_ex If Logger has an initialization failed
        @throw std::runtime_error If file reader could not determine for <fileName>. 
        If file reader could not open <fileName> for reading.
        */
        Parser(std::string fileName);


        /**
        @brief The main method to analyze raw packets, regardless of whether we analyze the raw packets
        cought through the network interface or read them from .pcap file 
        */
        void run(); // main method for start work the Parser (read file or capture)

        /**
        @brief Display information to the console after analyzing raw packets
        */
        void showResult();

        /**
        @brief Get the size of the container in which the information from the analyzed packets is stored
        \warning The containter will be storing some information if packets were captured from network 
        interface via working mode 'full' or 'protei', or if packets were read from a .pcap file
        */
        size_t sizePacketsInfo() { return packetsInfo.size(); }

        /**
        @brief Get the size of the container in which analyzed packets are stored
        */
        size_t sizeParsedPacketVec() { return parsedPacketVec.size(); }

        ~Parser();
    };

}
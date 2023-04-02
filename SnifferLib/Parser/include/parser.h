// #pragma once
#include <iostream>
#include "PcapLiveDeviceList.h" //representing network interface (PcapLiveDevice for Linux)
#include "stdlib.h"
#include "SystemUtils.h" //several useful utilities for interaction with OS
#include "packetStats.h" //mine class for statistics of protocols

namespace pars
{
    using timeout = unsigned long long;
    using vecStr = std::vector<std::string>;
    using PacketVector = std::vector<pcpp::Packet>;

    class Parser
    {
    private:
        pcpp::PcapLiveDevice *device;       // network interface
        pcpp::RawPacketVector rawVec;       // RawPackets' vector
        pars::timeout timeCapture;          // time to capture RawPackets

        pars::PacketVector parsedPacketVec; // already parsed Packets' vector
        pars::stats::PacketStats stats;     // to get statistics about Packets
        pars::vecStr packetsInfo;           // lines with full extracted data from each protocols

        void briefInfoPackets();

    public:
        Parser(std::string interfaceName, timeout timeCapture);

        void startSniff();
    };
}
//#pragma once
#include <iostream>
#include "PcapLiveDeviceList.h" //representing network interface (PcapLiveDevice for Linux)
#include "stdlib.h"
#include "SystemUtils.h"        //several useful utilities for interaction with OS
#include "packetStats.h"        //mine class for statistics of protocols

namespace pars
{
    using timeout = unsigned long long;
    using vecStr = std::vector<std::string>;
    //using PacketVector = std::vector<pcpp::Packet>;

    class Parser
    {
    private:
        pcpp::PcapLiveDevice *device; 
        pcpp::RawPacketVector rawVec;

        pars::timeout timeCapture;
        pars::vecStr packetsInfo;
        pars::stats::PacketStats stats;

    public:
        Parser(std::string interfaceName, timeout timeCapture);

        void startSniff();
    };
}
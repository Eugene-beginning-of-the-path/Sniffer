//#pragma once
#include <iostream>
#include <Packet.h>

namespace pars
{
    namespace stats
    {
        class PacketStats
        {
        private:
            int ethPacketCount;
            int ipv4PacketCount;
            int ipv6PacketCount;
            int tcpPacketCount;
            int udpPacketCount;
            int dnsPacketCount;
            int httpPacketCount;
            int sslPacketCount;

            // Clear all stats
            void clear()
            {
                ethPacketCount = 0;
                ipv4PacketCount = 0;
                ipv6PacketCount = 0;
                tcpPacketCount = 0;
                udpPacketCount = 0;
                tcpPacketCount = 0;
                dnsPacketCount = 0;
                httpPacketCount = 0;
                sslPacketCount = 0;
            }

        public:
            PacketStats() { clear(); }

            // Collect stats from a packet
            void consumePacket(pcpp::Packet &packet);

            // Print stats to console
            void printToConsole();
        };

    }
}
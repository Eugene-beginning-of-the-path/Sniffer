//#pragma once
#include <iostream>
#include <Packet.h>

/// @file

namespace pars
{
    /**
    * \namespace stats
    * \brief The namespace has support class for the statistics about captured packets 
    */
    namespace stats
    {
        /**
	    * @class PacketStats
	    * \brief The suppot class that can count protocols based on captured packets 
        * \details This class instended for counting protocols from received parsed packets.
        * If we transfer several parsed packets to this class for operation, we will get
        * the total number of protocols from all transmitted packets.
	    */
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

            /**
            @brief Just construction of the class. The internal counters are reset to zero 
            */
            PacketStats() { clear(); }

            /**
            @brief Count number of porotocls of parsed packet
            @param[in] packet An object of already parsed packet
            */
            void consumePacket(pcpp::Packet &packet); // Collect stats from a packet

            /**
            @brief Display to the console the number of counted protocols 
            */
            void printToConsole(); // Print stats to console
        };

    }
}
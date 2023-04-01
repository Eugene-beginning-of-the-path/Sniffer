//#include <iostream>
//#include "stdlib.h"
//#include "PcapLiveDeviceList.h"
//#include "SystemUtils.h"

#include "TcpLayer.h"
#include "EthLayer.h"

#include "parser.h"
//#include "packetStats.h"


std::string printTcpFlags(pcpp::TcpLayer* tcpLayer)
{
    std::string result = "";
    if (tcpLayer->getTcpHeader()->synFlag == 1)
        result += "SYN ";
    if (tcpLayer->getTcpHeader()->ackFlag == 1)
        result += "ACK ";
    if (tcpLayer->getTcpHeader()->pshFlag == 1)
        result += "PSH ";
    if (tcpLayer->getTcpHeader()->cwrFlag == 1)
        result += "CWR ";
    if (tcpLayer->getTcpHeader()->urgFlag == 1)
        result += "URG ";
    if (tcpLayer->getTcpHeader()->eceFlag == 1)
        result += "ECE ";
    if (tcpLayer->getTcpHeader()->rstFlag == 1)
        result += "RST ";
    if (tcpLayer->getTcpHeader()->finFlag == 1)
        result += "FIN ";

    return result;
}

/**
 * main method of the application
 */
int main(int argc, char* argv[])
{
	// //IPv4 address of the interface we want to sniff
	// //std::string interfaceIPAddr = "127.0.0.1";
	
	// //find the instance class to use network interface
	// //PcapLiveDevice or WinPcapLiveDevice (according to the operating system the application is running on) 
	// pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName("eth0");
	// if (dev == NULL)
	// {
	// 	//std::cerr << "Cannot find interface with IPv4 address of <" << interfaceIPAddr << ">" << std::endl;
	// 	return 1;
	// }

	// if (!dev->open())
	// {
	// 	std::cerr << "Cannot open device" << std::endl;
	// 	return 1;
	// }

	// //pcpp::PortFilter portFilter(80, pcpp::SRC_OR_DST);
	// //pcpp::AndFilter andFilter;(&portFilter);

	// pcpp::RawPacketVector rawVector;
	
	// dev->startCapture(rawVector);
	// pcpp::multiPlatformSleep(10);
	// dev->stopCapture();

	// std::cout << rawVector.size() << std::endl;

	// PacketStats stats;
	// for	(auto iter = rawVector.begin(); iter != rawVector.end(); iter++)
	// {
	// 	// parse raw packet
    // 	pcpp::Packet parsedPacket(*iter);
			
    // 	// feed packet to the stats object
    // 	stats.consumePacket(parsedPacket);
	// }
	// stats.printToConsole();
	// //pcpp::RawPacket raw(*rawVector.begin());
	// pcpp::Packet parsedPacket(*rawVector.begin());

	// pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();

	// if (ethernetLayer == NULL)
	// {
	// 	std::cout << "None TCP layer";
	// 	return 1;
	// }
	// std::cout << std::endl
    // << "Source MAC address: " << ethernetLayer->getSourceMac() << std::endl
    // << "Destination MAC address: " << ethernetLayer->getDestMac() << std::endl
    // << "Ether type = 0x" << std::hex << pcpp::netToHost16(ethernetLayer->getEthHeader()->etherType) << std::endl;

	pars::Parser parser("eth0", 15);
	parser.startSniff();

	return 0;
}
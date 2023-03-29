#include <iostream>
#include "stdlib.h"
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"



/**
 * main method of the application
 */
int main(int argc, char* argv[])
{
	// IPv4 address of the interface we want to sniff
	std::string interfaceIPAddr = "127.0.0.1";

	// find the interface by IP address
	pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr);
	if (dev == NULL)
	{
		std::cerr << "Cannot find interface with IPv4 address of '" << interfaceIPAddr << "'" << std::endl;
		return 1;
	}

    std::cout << "Full Successful" << std::endl;
}
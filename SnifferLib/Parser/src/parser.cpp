#include "parser.h"

pars::Parser::Parser(std::string interfaceName, timeout timeCapture) : device(NULL),
                                                                       timeCapture(timeCapture)
{
    device = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(interfaceName);

    if (device == NULL)
    {
        std::cerr << "Cannot find interface with name <" << interfaceName << ">" << std::endl;
        // throw exception!!-------------------//
    }

    if (!device->open())
    {
        std::cerr << "Cannot open device <" << interfaceName << ">" << std::endl;
        // throw exception!!-------------------//
    }
}

void pars::Parser::startSniff()
{
    device->startCapture(rawVec);
    pcpp::multiPlatformSleep(timeCapture);
    device->stopCapture();

    // or brief information via PacketStats;
    // or full information via parsing xLayer;

    // brief information:
    for (auto iter = rawVec.begin(); iter != rawVec.end(); iter++)
    {
        pcpp::Packet parsedPacket(*iter);
        stats.consumePacket(parsedPacket);
    }
    stats.printToConsole();
}
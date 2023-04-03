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
    parsedPacketVec.clear();
}

void pars::Parser::startSniff()
{
    device->startCapture(rawVec);
    pcpp::multiPlatformSleep(timeCapture);
    device->stopCapture();

    // brief information via PacketsStats:
    // briefInfoPackets();

    // or full information via parsing xLayer:
    int i = 1;
    for (auto iter = rawVec.begin(); iter != rawVec.end(); iter++)
    {
        parsedPacketVec.push_back(pcpp::Packet(*iter));

        stats.consumePacket(parsedPacketVec.back());

        std::string lineStart = "Packet #";
        lineStart.append(std::to_string(i));
        lineStart.append(":");
        packetsInfo.push_back(lineStart + getInfoProtocol(parsedPacketVec.back().getFirstLayer()));
        i++;
    }
    stats.printToConsole();

    std::cout << std::endl;
    for (auto i = packetsInfo.begin(); i != packetsInfo.end(); i++)
    {
        std::cout << *i;
    }
}

void pars::Parser::briefInfoPackets()
{
    for (auto iter = rawVec.begin(); iter != rawVec.end(); iter++)
    {
        parsedPacketVec.push_back(pcpp::Packet(*iter));

        stats.consumePacket(parsedPacketVec.back());
    }
    stats.printToConsole();
}

std::string pars::Parser::getInfoProtocol(pcpp::Layer *curLayer)
{
    switch (curLayer->getProtocol())
    {
    case (pcpp::Ethernet):
        return reassemblyEth(dynamic_cast<pcpp::EthLayer*>(curLayer));
        break;

    case (pcpp::IPv4):
        return reassemblyIPv4(dynamic_cast<pcpp::IPv4Layer*>(curLayer));
        break;
    }

    std::vector<int> vec = {100, 200, 300};
    std::cout << *(vec.begin()++);

    return "---";
}

std::string pars::Parser::reassemblyEth(pcpp::EthLayer *ethLayer)
{
    std::string info = "\n\tEthernet:\n";

    info.append("\t\t>Source MAC address: " + ethLayer->getSourceMac().toString() + '\n');
    info.append("\t\t>Destination MAC address: " + ethLayer->getDestMac().toString() + '\n');
    if (ethLayer->getEthHeader() != NULL)
        info.append("\t\t>Ethernet Type: " + std::to_string(ethLayer->getEthHeader()->etherType) + '\n');
    info.append("\t\t>Payload size: " + ethLayer->getLayerPayloadSize() + '\n');
    info.append("\n");
    return info;
}

std::string pars::Parser::reassemblyIPv4(pcpp::IPv4Layer *ipLayer)
{
    std::string info = "\n\tIPv4:\n";

    info.append("\t\t>Destination IP: " + ipLayer->getDstIPAddress().toString() + '\n');
    info.append("\t\t>Source IP: " + ipLayer->getSrcIPAddress().toString() + '\n');
    info.append("\t\t>Header lenght: " + ipLayer->getHeaderLen() + '\n');
    if (ipLayer->getIPv4Header() != NULL)
    {
        info.append("\t\t|\t-IP id: " + std::to_string(ipLayer->getIPv4Header()->ipId));
        info.append("\t\t|\t-Time live: " + std::to_string(ipLayer->getIPv4Header()->timeToLive));
        info.append("\t\t|\t-Total len: " + std::to_string(ipLayer->getIPv4Header()->totalLength));
        info.append("\t\t|\t-Header checksum: " + std::to_string(ipLayer->getIPv4Header()->headerChecksum));
        info.append("\t\t|\t-Protocol: " + std::to_string(ipLayer->getIPv4Header()->protocol));
    }
    if (ipLayer->getFirstOption().isNull() != true)
    {
        info.append("\t\tOptions:\n");
        
        for (auto i = ipLayer->getFirstOption(); i.isNull() != true; 
        i = ipLayer->getNextOption(i))
        {
            info.append("\t\t|\t-" + IPv4optionTypeToString(i.getIPv4OptionType()) + ": " + std::to_string(*i.getValue()) + '\n');
        }
    }

    return info;
}

std::string pars::Parser::IPv4optionTypeToString(pcpp::IPv4OptionTypes type)
{
    switch(type)
    {
        case pcpp::IPV4OPT_NOP:
            return "NOP: ";
        case pcpp::IPV4OPT_RecordRoute:
            return "Record route: ";
        case pcpp::IPV4OPT_MTUProbe:
            return "MTU probe: ";
        case pcpp::IPV4OPT_MTUReply:
            return "MTU reply: ";
        case pcpp::IPV4OPT_QuickStart:
            return "Quick start: ";
        case pcpp::IPV4OPT_Timestamp:
            return "Timestamp: ";
        case pcpp::IPV4OPT_Traceroute:
            return "Traceroute: ";
        case pcpp::IPV4OPT_Security:
            return "Security: ";
        case pcpp::IPV4OPT_LooseSourceRoute:
            return "Loose source route: ";
        case pcpp::IPV4OPT_ExtendedSecurity:
            return "Extended security: ";
        case pcpp::IPV4OPT_CommercialSecurity:
            return "Commercial security: ";
        case pcpp::IPV4OPT_StreamID:
            return "Stream ID: ";
        case pcpp::IPV4OPT_StrictSourceRoute:
            return "Strict source route: ";
        case pcpp::IPV4OPT_ExtendedInternetProtocol:
            return "Extended IP:";
        case pcpp::IPV4OPT_AddressExtension:
            return "Address extension: ";
        case pcpp::IPV4OPT_RouterAlert :
            return "Router alert: ";
        case pcpp::IPV4OPT_SelectiveDirectedBroadcast :
            return "Selective directed broadcast: ";
        case pcpp::IPV4OPT_DynamicPacketState:
            return "SCPS Corruption Experienced: ";
        case pcpp::IPV4OPT_UpstreamMulticastPkt:
            return "Upstream multicast Pkt: ";
        case pcpp::IPV4OPT_Unknown :
            return "Unknown option: ";
        case pcpp::IPV4OPT_EndOfOptionsList:
            return "End of Options List";
        default:
            return "Error";
    }
}
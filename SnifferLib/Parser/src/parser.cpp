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
    int number = 1;
    for (auto iter = rawVec.begin(); iter != rawVec.end(); iter++)
    {
        parsedPacketVec.push_back(pcpp::Packet(*iter));

        stats.consumePacket(parsedPacketVec.back());

        std::string lineStart = "\n\n Packet #";
        lineStart.append(std::to_string(number));
        lineStart.append(":");
        packetsInfo.push_back(pars::vecStr{""});
        packetsInfo[number - 1].push_back(lineStart);

        // std::cout << reassemblyEth(parsedPacketVec.back().getLayerOfType<pcpp::EthLayer>()) << std::endl;

        for (auto i = parsedPacketVec.back().getFirstLayer(); i != NULL; i = i->getNextLayer())
        {
            packetsInfo[number - 1].push_back(getInfoProtocol(i));
        }

        number++;
    }
    stats.printToConsole();

    std::cout << std::endl;
    // for (auto i = packetsInfo.begin(); i != packetsInfo.end(); i++)
    //     for (auto j = *i.begin(); j != j.end(); j++)
    //     {
    //         std::cout << *j;
    //     }
    for (auto vectors : packetsInfo)
        for (auto strings : vectors)
            std::cout << strings;
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
        return reassemblyEth(dynamic_cast<pcpp::EthLayer *>(curLayer));
        break;

    case (pcpp::IPv4):
        return reassemblyIPv4(dynamic_cast<pcpp::IPv4Layer *>(curLayer));
        break;

    case (pcpp::IPv6):
        return reassemblyIPv6(dynamic_cast<pcpp::IPv6Layer *>(curLayer));
        break;

    case (pcpp::TCP):
        return reassemblyTcp(dynamic_cast<pcpp::TcpLayer *>(curLayer));
        break;

    case (pcpp::UDP):
        return reassemblyUdp(dynamic_cast<pcpp::UdpLayer *>(curLayer));
        break;

    default:
        return "\n\tUnknown protocol\n";
    }
}

std::string pars::Parser::reassemblyEth(pcpp::EthLayer *ethLayer)
{
    if (ethLayer != NULL)
    {
        std::string info = "\n\tEthernet:\n";

        info.append("\t\t>Source MAC address: " + ethLayer->getSourceMac().toString() + '\n');
        info.append("\t\t>Destination MAC address: " + ethLayer->getDestMac().toString() + '\n');
        if (ethLayer->getEthHeader() != NULL)
            info.append("\t\t>Ethernet Type: " + std::to_string(ethLayer->getEthHeader()->etherType) + '\n');

        info.append("\t\t>Payload size: " + std::to_string(ethLayer->getLayerPayloadSize()) + '\n');

        return info;
    }
}

std::string pars::Parser::reassemblyIPv4(pcpp::IPv4Layer *ipLayer)
{
    std::string info = "\n\tIPv4:\n";

    info.append("\t\t>Destination IP: " + ipLayer->getDstIPAddress().toString() + '\n');
    info.append("\t\t>Source IP: " + ipLayer->getSrcIPAddress().toString() + '\n');
    info.append("\t\t>Header lenght: " + std::to_string(ipLayer->getHeaderLen()) + '\n');
    if (ipLayer->getIPv4Header() != NULL)
    {
        info.append("\t\t>into Header:\n");
        info.append("\t\t|\t-IP id: " + std::to_string(ipLayer->getIPv4Header()->ipId) + '\n');
        info.append("\t\t|\t-Time live: " + std::to_string(ipLayer->getIPv4Header()->timeToLive) + '\n');
        info.append("\t\t|\t-Total len: " + std::to_string(ipLayer->getIPv4Header()->totalLength) + '\n');
        info.append("\t\t|\t-Header checksum: " + std::to_string(ipLayer->getIPv4Header()->headerChecksum) + '\n');
        info.append("\t\t|\t-Protocol: " + std::to_string(ipLayer->getIPv4Header()->protocol) + '\n');
    }
    if (ipLayer->getFirstOption().isNull() != true)
    {
        info.append("\t\t>IPv4 Options:\n");

        for (auto i = ipLayer->getFirstOption(); i.isNull() != true;
             i = ipLayer->getNextOption(i))
        {
            info.append("\t\t|\t-" + IPv4OptionTypeToString(i.getIPv4OptionType()) + std::to_string(*i.getValue()) + '\n');
        }
    }

    return info;
}

std::string pars::Parser::IPv4OptionTypeToString(pcpp::IPv4OptionTypes type)
{
    switch (type)
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
    case pcpp::IPV4OPT_RouterAlert:
        return "Router alert: ";
    case pcpp::IPV4OPT_SelectiveDirectedBroadcast:
        return "Selective directed broadcast: ";
    case pcpp::IPV4OPT_DynamicPacketState:
        return "SCPS Corruption Experienced: ";
    case pcpp::IPV4OPT_UpstreamMulticastPkt:
        return "Upstream multicast Pkt: ";
    case pcpp::IPV4OPT_Unknown:
        return "Unknown option: ";
    case pcpp::IPV4OPT_EndOfOptionsList:
        return "End of Options List";
    default:
        return "Error IPv4 Option Type";
    }
}

std::string pars::Parser::reassemblyIPv6(pcpp::IPv6Layer *ipLayer)
{
    std::string info = "\n\tIPv6:\n";

    info.append("\t\t>Destination IP: " + ipLayer->getDstIPAddress().toString() + '\n');
    info.append("\t\t>Source IP: " + ipLayer->getSrcIPAddress().toString() + '\n');
    info.append("\t\t>Header lenght: " + std::to_string(ipLayer->getHeaderLen()) + '\n');
    if (ipLayer->getIPv6Header() != NULL)
    {
        info.append("\t\t>into Header:\n");
        info.append("\t\t|\t-Time to live: " + std::to_string(ipLayer->getIPv6Header()->hopLimit) + '\n');
        info.append("\t\t|\t-IP version number: " + std::to_string(ipLayer->getIPv6Header()->ipVersion) + '\n');
        info.append("\t\t|\t-Payload size: " + std::to_string(ipLayer->getIPv6Header()->payloadLength) + '\n');
        info.append("\t\t|\t-Traffic class: " + std::to_string(ipLayer->getIPv6Header()->trafficClass) + '\n');
    }
    info.append("\t\t>Number of IPv6 extensions: " + std::to_string(ipLayer->getHeaderLen()) + '\n');

    return info;
}

std::string pars::Parser::reassemblyTcp(pcpp::TcpLayer *tcpLayer)
{
    std::string info = "\n\tTCP:\n";

    info.append("\t\t>Source port: " + std::to_string(tcpLayer->getSrcPort()) + '\n');
    info.append("\t\t>Destination port: " + std::to_string(tcpLayer->getDstPort()) + '\n');
    info.append("\t\t>Header len: " + std::to_string(tcpLayer->getHeaderLen()) + '\n');
    if (tcpLayer->getTcpHeader() != NULL)
    {
        info.append("\t\t>into Header:\n");
        if (tcpLayer->getTcpHeader()->synFlag == 1)
            info.append("\t\t|\t-SYN flag: " + std::to_string(tcpLayer->getTcpHeader()->synFlag) + '\n');
        if (tcpLayer->getTcpHeader()->ackFlag == 1)
            info.append("\t\t|\t-Acknowledgment number: " + std::to_string(tcpLayer->getTcpHeader()->ackFlag) + '\n');
        if (tcpLayer->getTcpHeader()->pshFlag == 1)
            info.append("\t\t|\t-PSH flag: " + std::to_string(tcpLayer->getTcpHeader()->pshFlag) + '\n');
        if (tcpLayer->getTcpHeader()->cwrFlag == 1)
            info.append("\t\t|\t-CWR flag: " + std::to_string(tcpLayer->getTcpHeader()->cwrFlag) + '\n');
        if (tcpLayer->getTcpHeader()->urgFlag == 1)
            info.append("\t\t|\t-URG flag: " + std::to_string(tcpLayer->getTcpHeader()->urgFlag) + '\n');
        if (tcpLayer->getTcpHeader()->eceFlag == 1)
            info.append("\t\t|\t-ECE flag: " + std::to_string(tcpLayer->getTcpHeader()->eceFlag) + '\n');
        if (tcpLayer->getTcpHeader()->rstFlag == 1)
            info.append("\t\t|\t-RST flag: " + std::to_string(tcpLayer->getTcpHeader()->rstFlag) + '\n');
        if (tcpLayer->getTcpHeader()->finFlag == 1)
            info.append("\t\t|\t-FIN flag: " + std::to_string(tcpLayer->getTcpHeader()->finFlag) + '\n');

        info.append("\t\t|\t-Size of the recieve window: " + std::to_string(tcpLayer->getTcpHeader()->windowSize) + '\n');
        info.append("\t\t|\t-Sequence number: " + std::to_string(tcpLayer->getTcpHeader()->sequenceNumber) + '\n');
        info.append("\t\t|\t-Checksum field: " + std::to_string(tcpLayer->getTcpHeader()->headerChecksum) + '\n');
        info.append("\t\t|\t-Size of the TCP header in 32-bit words: " + std::to_string(tcpLayer->getTcpHeader()->headerChecksum) + '\n');
    }

    if (tcpLayer->getFirstTcpOption().isNull() != true)
    {
        info.append("\t\t>TCP Options:\n");

        for (auto i = tcpLayer->getFirstTcpOption(); i.isNull() != true; i = tcpLayer->getNextTcpOption(i))
        {
            info.append("\t\t|\t-" + TcpOptionTypeToString(i.getTcpOptionType()) + std::to_string(*i.getValue()) + '\n');
        }
    }

    return info;
}

std::string pars::Parser::TcpOptionTypeToString(pcpp::TcpOptionType type)
{
    switch (type)
    {
    case pcpp::PCPP_TCPOPT_NOP:
        return "NOP: ";
    case pcpp::PCPP_TCPOPT_EOL:
        return "EOL: ";
    case pcpp::TCPOPT_MSS:
        return "MSS: ";
    case pcpp::PCPP_TCPOPT_WINDOW:
        return "WINDOW: ";
    case pcpp::TCPOPT_SACK_PERM:
        return "SACK Permitted: ";
    case pcpp::PCPP_TCPOPT_SACK:
        return "SACK Block: ";
    case pcpp::TCPOPT_ECHO:
        return "Echo: ";
    case pcpp::TCPOPT_ECHOREPLY:
        return "Echo Reply: ";
    case pcpp::PCPP_TCPOPT_TIMESTAMP:
        return "TCP Timestamps: ";
    case pcpp::TCPOPT_CC:
        return "CC: ";
    case pcpp::TCPOPT_CCNEW:
        return "CC.NEW: ";
    case pcpp::TCPOPT_CCECHO:
        return "CC.ECHO: ";
    case pcpp::TCPOPT_MD5:
        return "MD5 Signature: ";
    case pcpp::TCPOPT_MPTCP:
        return "Multipath TCP:";
    case pcpp::TCPOPT_SCPS:
        return "SCPS Capabilities: ";
    case pcpp::TCPOPT_SNACK:
        return "SCPS SNACK: ";
    case pcpp::TCPOPT_RECBOUND:
        return "SCPS Record Boundary: ";
    case pcpp::TCPOPT_CORREXP:
        return "SCPS Corruption Experienced: ";
    case pcpp::TCPOPT_QS:
        return "Quick-Start Response: ";
    case pcpp::TCPOPT_USER_TO:
        return "User Timeout Option: ";
    case pcpp::TCPOPT_EXP_FD:
        return "RFC3692-style Experiment 1: ";
    case pcpp::TCPOPT_EXP_FE:
        return "RFC3692-style Experiment 2: ";
    case pcpp::TCPOPT_RVBD_PROBE:
        return "Riverbed probe option: ";
    case pcpp::TCPOPT_RVBD_TRPY:
        return "Riverbed transparency option: ";
    case pcpp::TCPOPT_Unknown:
        return "Unknown option: ";
    default:
        return "Error Tcp Option Type";
    }
}

std::string pars::Parser::reassemblyUdp(pcpp::UdpLayer *udpLayer)
{
    std::string info = "\n\tUDP:\n";

    info.append("\t\t>Source port: " + std::to_string(udpLayer->getSrcPort()) + '\n');
    info.append("\t\t>Destination port: " + std::to_string(udpLayer->getDstPort()) + '\n');
    info.append("\t\t>Header len: " + std::to_string(udpLayer->getHeaderLen()) + '\n');
    info.append("\t\t>Payload size: " + std::to_string(udpLayer->getLayerPayloadSize()) + '\n');
    if (udpLayer->getUdpHeader() != NULL)
    {
        info.append("\t\t>into Header:\n");
        info.append("\t\t|\t-Length of header and payload in bytes: " + std::to_string(udpLayer->getUdpHeader()->length) + '\n');
        info.append("\t\t|\t-Checksum field: " + std::to_string(udpLayer->getUdpHeader()->headerChecksum) + '\n');
    }

    return info;
}

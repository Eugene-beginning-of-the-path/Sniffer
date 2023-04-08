#include "parser.h"

pars::Parser::Parser(std::string interfaceName, timeout timeCapture, std::string workMode) : device(NULL), timeCapture(timeCapture), workMode(workMode)
{
    logger = spdlog::basic_logger_mt<spdlog::async_factory>("async_file_logger", "logs/SnifferLogs.txt");


    device = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(interfaceName);

    if (device == NULL)
    {
        logger->info("Error >Cannot find interface with name <" + interfaceName + ">");
        throw std::runtime_error("Error >Cannot find interface with name <" + interfaceName + ">");
    }

    if (!device->open())
    {
        // std::cerr << "Cannot open device <" << interfaceName << ">" << std::endl;
        throw std::runtime_error("Error >Cannot open device <" + interfaceName + ">");
    }

    parsedPacketVec.clear();
}

void pars::Parser::startSniff()
{
    device->startCapture(rawVec);
    pcpp::multiPlatformSleep(timeCapture);
    device->stopCapture();

    if (workMode == "brief")
        briefInfo(); // brief information via PacketsStats
    else if (workMode == "full")
        fullInfo();                // full information via parsing all protocols
    else if (workMode == "protei") // special task for Protey (counting all URL from HTTP)
        specialTaskInfo();
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

    case (pcpp::DNS):
        return reassemblyDns(dynamic_cast<pcpp::DnsLayer *>(curLayer));
        break;

    case (pcpp::HTTPRequest):
        return reassemblyHttpRequest(dynamic_cast<pcpp::HttpRequestLayer *>(curLayer));
        break;

    case (pcpp::HTTPResponse):
        return reassemblyHttpResponse(dynamic_cast<pcpp::HttpResponseLayer *>(curLayer));
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

std::string pars::Parser::reassemblyDns(pcpp::DnsLayer *dnsLayer)
{
    std::string info = "\n\tDNS:\n";

    info.append("\t\t>Size of the DNS data : " + std::to_string(dnsLayer->getHeaderLen()) + '\n');
    info.append("\t\t>Payload size: " + std::to_string(dnsLayer->getLayerPayloadSize()) + '\n');
    info.append("\t\t>Query count: " + std::to_string(dnsLayer->getQueryCount()) + '\n');
    info.append("\t\t>Answer count: " + std::to_string(dnsLayer->getAnswerCount()) + '\n');
    info.append("\t\t>Authority count: " + std::to_string(dnsLayer->getAuthorityCount()) + '\n');
    info.append("\t\t>Additional record count: " + std::to_string(dnsLayer->getAdditionalRecordCount()) + '\n');

    if (dnsLayer->getDnsHeader() != NULL)
    {
        info.append("\t\t>into Header:\n");
        info.append("\t\t|\t-DNS Query ID: " + std::to_string(dnsLayer->getDnsHeader()->transactionID) + '\n');
        info.append("\t\t|\t-Number DNS query records: " + std::to_string(dnsLayer->getDnsHeader()->numberOfQuestions) + '\n');
        info.append("\t\t|\t-Number DNS answer records: " + std::to_string(dnsLayer->getDnsHeader()->numberOfAnswers) + '\n');
        info.append("\t\t|\t-Number authority records: " + std::to_string(dnsLayer->getDnsHeader()->numberOfAuthority) + '\n');
        info.append("\t\t|\t-Number additional records: " + std::to_string(dnsLayer->getDnsHeader()->numberOfAdditional) + '\n');
    }
    if (dnsLayer->getFirstQuery() != NULL)
    {
        info.append("\t\t>DNS query:\n");

        auto query = dnsLayer->getFirstQuery();
        for (auto i = 0; i < dnsLayer->getQueryCount(); i++)
        {

            info.append("\t\t|\t-Query size: " + std::to_string(query->getSize()) + '\n');
            info.append("\t\t|\t-Query type: " + DnsTypeToString(query->getType()) + '\n');

            if (i + 1 != dnsLayer->getQueryCount())
                info.append("\t\t|\n");

            query = dnsLayer->getNextQuery(query);
        }
    }
    if (dnsLayer->getFirstAnswer() != NULL)
    {
        info.append("\t\t>DNS answer:\n");

        auto answer = dnsLayer->getFirstAnswer();
        for (auto i = 0; i < dnsLayer->getAnswerCount(); i++)
        {
            info.append("\t\t|\t-The time-to-leave value (this record): " + std::to_string(answer->getTTL()) + '\n');
            info.append("\t\t|\t-Data length value (this record): " + std::to_string(answer->getDataLength()) + '\n');
            info.append("\t\t|\t-Total size in bytes (this record): " + std::to_string(answer->getSize()) + '\n');
            info.append("\t\t|\t-Query type: " + DnsTypeToString(answer->getType()) + '\n');

            if (i + 1 != dnsLayer->getAnswerCount())
                info.append("\t\t|\n");

            answer = dnsLayer->getNextAnswer(answer);
        }
    }

    return info;
}

std::string pars::Parser::DnsTypeToString(pcpp::DnsResourceType type)
{
    switch (type)
    {
    case pcpp::DnsQueryType:
        return "DNS query record";
        break;

    case pcpp::DnsAnswerType:
        return "DNS answer record";
        break;

    case pcpp::DnsAuthorityType:
        return "DNS authority record";
        break;

    case pcpp::DnsAdditionalType:
        return "DNS additional record";
        break;

    default:
        return "Error Query Type";
    }
}

std::string pars::Parser::reassemblyHttpRequest(pcpp::HttpRequestLayer *httpReqLayer)
{
    std::string info = "\n\tHTTP(request):\n";

    if (httpReqLayer->getFirstLine() != nullptr)
    {
        info.append("\t\t>Size: " + std::to_string(httpReqLayer->getFirstLine()->getSize()) + '\n');
        // info.append("\t\t>Is complete: " + std::to_string((int)(httpRequestLayer->getFirstLine()->isComplete())) + '\n');
        info.append("\t\t>Method: " + printHttpMethod(httpReqLayer->getFirstLine()->getMethod()) + '\n');
        info.append("\t\t>URI: " + httpReqLayer->getFirstLine()->getUri() + '\n');
    }
    if (httpReqLayer->getFieldByName(PCPP_HTTP_HOST_FIELD) != nullptr)
    {
        info.append("\t\t>Host: " + httpReqLayer->getFieldByName(PCPP_HTTP_HOST_FIELD)->getFieldValue() + '\n');
    }
    if (httpReqLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD) != nullptr)
    {
        info.append("\t\t>User-agent: " + httpReqLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD)->getFieldValue() + '\n');
    }
    if (httpReqLayer->getFieldByName(PCPP_HTTP_COOKIE_FIELD) != nullptr)
    {
        info.append("\t\t>Cookie: " + httpReqLayer->getFieldByName(PCPP_HTTP_COOKIE_FIELD)->getFieldValue() + '\n');
    }

    info.append("\t\t>HTTP full URL: " + httpReqLayer->getUrl() + '\n');

    if (countUrl.find(httpReqLayer->getFieldByName(PCPP_HTTP_HOST_FIELD)->getFieldValue()) != countUrl.end())
        countUrl.find(httpReqLayer->getFieldByName(PCPP_HTTP_HOST_FIELD)->getFieldValue())->second += 1;
    else
        countUrl[httpReqLayer->getFieldByName(PCPP_HTTP_HOST_FIELD)->getFieldValue()] = 1;

    return info;
}

std::string pars::Parser::printHttpMethod(pcpp::HttpRequestLayer::HttpMethod httpMethod)
{
    switch (httpMethod)
    {
    case pcpp::HttpRequestLayer::HttpGET:
        return "GET";
    case pcpp::HttpRequestLayer::HttpPOST:
        return "POST";
    default:
        return "Other";
    }
}

std::string pars::Parser::reassemblyHttpResponse(pcpp::HttpResponseLayer *httpResLayer)
{
    std::string info = "\n\tHTTP(response):\n";

    if (httpResLayer->getFirstLine() != NULL)
    {
        info.append("\t\t>Size: " + std::to_string(httpResLayer->getFirstLine()->getSize()) + '\n');
        info.append("\t\t>Status code: " + httpResLayer->getFirstLine()->getStatusCodeString() + '\n');
        info.append("\t\t>Status code number: " + std::to_string(httpResLayer->getFirstLine()->getStatusCodeAsInt()) + '\n');
        info.append("\t\t>HTTP version: " + std::to_string(httpResLayer->getFirstLine()->getVersion()) + '\n');
    }

    info.append("\t\t>Content size: " + std::to_string(httpResLayer->getContentLength()) + '\n');

    return info;
}

std::string pars::Parser::printHttpVersion(pcpp::HttpVersion version)
{
    switch (version)
    {
    case pcpp::HttpVersion::ZeroDotNine:
        return "Http/0.9";
    case pcpp::HttpVersion::OneDotZero:
        return "Http/1.0";
    case pcpp::HttpVersion::OneDotOne:
        return "Http/1.1";
    default:
        return "Unknown version";
    }
}

void pars::Parser::specialTaskInfo()
{
    fullInfo();

    std::cout << std::endl
              << "-----------------------------------------------------\n\n";
    std::cout << "Protei task:\n";

    for (std::map<std::string, int>::iterator iterMap = countUrl.begin(); iterMap != countUrl.end();
         iterMap++)
    {
        std::cout << "\t URL:'" << iterMap->first << "' = " << iterMap->second << std::endl;
    }

    std::cout << std::endl;
}

void pars::Parser::fullInfo()
{
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

        for (auto i = parsedPacketVec.back().getFirstLayer(); i != NULL; i = i->getNextLayer())
        {
            packetsInfo[number - 1].push_back(getInfoProtocol(i));
        }

        number++;
    }
    stats.printToConsole();

    std::cout << std::endl;

    for (auto vectors : packetsInfo)
        for (auto strings : vectors)
            std::cout << strings;
}

void pars::Parser::briefInfo()
{
    for (auto iter = rawVec.begin(); iter != rawVec.end(); iter++)
    {
        pcpp::Packet parsedPacket(*iter);
        stats.consumePacket(parsedPacket);
    }

    stats.printToConsole();
}

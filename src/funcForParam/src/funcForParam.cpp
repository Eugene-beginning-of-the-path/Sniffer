#include "funcForParam.h"

namespace conv
{
    std::string ParametrToStr(std::string str)
    {
        return str.substr(str.find_first_not_of('-', 0));
    }

    int ParametrToInt(std::string str)
    {
        return std::stoi(str.substr(str.find_first_not_of('-', 0)));
    }
}

namespace prmtrs
{
    void displayHelp()
    {
        std::cout << "Into if\n";
		std::cout << "Usage: \n"
				  << "\t*(1 way): snifferApp -<time_capture> -<name_interface> -<working_mode>\n"
				  << "\t**(2 way): snifferApp -<file_name.pcap>\n\n";

		std::cout << "Learn more about parameters:\n"
				  << "\t*For the (1 way):\n"
				  << "\t-<time_capture>: enter the packets capture time value in seconds.\n\n"
				  << "\t-<name_interface>: enter the name of the interface through which you want to listen to traffic\n"
				  << "\t\tyou can learn more about your interfaces using commands (ifconfig) or (ip addr).\n\n"
				  << "\t-<working_mode>: the application has 3 working mode.\n"
				  << "\t\t1. Working mode 'brief' will display you the number of protocols from the captured packets\n"
				  << "\t\t2. Working mode 'full' in addition to number of protocols from captured packets, it will also\n"
				  << "\t\tdisplay information from the headers of these protocols.\n"
				  << "\t\t3. Working mode 'protei' does the same things as the previously working modes, but also\n"
				  << "\t\tdisplay the numbers of URL at the end.\n\n"
				  << "\t-->Example for the (1 way): snifferApp -15 -eth0 -full\n\n"
				  << "\n\n\t**For the (2 way):\n"
				  << "\t-<file_name.pcap>: if you already have .pcap file with raw packets data, you can spectify that file \n"
				  << "\t\tand the application will display the information from that file.\n"
				  << "\t\tImportant - your file .pcap should be located in the 'build' folder.\n"
				  << "\n\t-->Example for the (2 way): snifferApp -input.pcap\n";
    }
}

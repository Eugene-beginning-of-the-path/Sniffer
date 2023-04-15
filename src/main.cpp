#include "parser.h"
#include "convertParam.h"

/**
 * main method of the application
 */
int main(int argc, char *argv[])
{
	try
	{
		pars::Parser parser(conv::ParametrToStr(argv[2]),
							conv::ParametrToInt(argv[1]), conv::ParametrToStr(argv[3]));

		//pars::Parser parser("input.pcap");
		parser.run();
		parser.showResult();
	}
	catch (const spdlog::spdlog_ex &ex)
	{
		std::cerr << "Log initialization failed: " << ex.what() << std::endl;
	}
	catch (const std::runtime_error &ex)
	{
		std::cerr << ex.what() << std::endl;
	}

	return 0;
}
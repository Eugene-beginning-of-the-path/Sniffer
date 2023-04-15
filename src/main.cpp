#include "parser.h"
#include "funcForParam.h"
#include "string.h"

/**
 * main method of the application
 */
int main(int argc, char *argv[])
{
	
	if (argc == 1)
	{
		prmtrs::displayHelp();
	}
	else if ((!strcmp("--help", argv[1])) || (argc == 1))
	{
		prmtrs::displayHelp();
	}
	else
	{
		try
		{
			if (argc == 2)
			{
				pars::Parser parser(conv::ParametrToStr(conv::ParametrToStr(argv[1])));
				parser.run();
				parser.showResult();
			}
			else
			{
				pars::Parser parser(conv::ParametrToStr(argv[2]),
									conv::ParametrToInt(argv[1]), conv::ParametrToStr(argv[3]));
				parser.run();
				parser.showResult();
			}
		}
		catch (const spdlog::spdlog_ex &ex)
		{
			std::cerr << "Log initialization failed: " << ex.what() << std::endl;
		}
		catch (const std::runtime_error &ex)
		{
			std::cerr << ex.what() << std::endl;
		}
	}
	
	return 0;
}
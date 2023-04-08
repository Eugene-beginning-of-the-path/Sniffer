#include "convertParam.h"

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

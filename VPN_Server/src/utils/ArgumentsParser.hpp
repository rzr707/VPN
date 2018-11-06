#ifndef COMMANDLINEPARSER_HPP
#define COMMANDLINEPARSER_HPP

#include "../ClientParameters.hpp"

namespace utils {
    class ArgumentsParser {
    public:
        ClientParameters parse(int argc, char** argv);
    private:
        /**
         * @brief SetDefaultSettings
         * Set parameters if they were not set by
         * user via terminal arguments on startup
         * @param in_param - pointer on reference of parameter string to check
         * @param type     - index of parameters
         */
        void setDefaultSettings(std::string *&in_param, size_t type);
    };
}

#endif // COMMANDLINEPARSER_HPP

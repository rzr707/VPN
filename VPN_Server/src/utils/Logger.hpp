#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <iostream>

namespace utils {
    class Logger {
    public:
        static void log(const std::string& msg,
                        std::ostream& s = std::cout);
    };
}

#endif // LOGGER_HPP

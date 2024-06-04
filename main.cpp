import Not.Dns;

#include <print>

auto main(int argc, char** argv) -> int
{
    if(argc != 2) {
        std::println("./not_dns <domain> !!!");
        return -1;
    }

    if(notD::resolve(argv[1]))
        return -1;

    return 0;
}


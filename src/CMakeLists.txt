add_library(notD Not.Dns_Packet.cpp)

target_sources(notD PUBLIC
    FILE_SET CXX_MODULES
        FILES
        Not.Dns.ixx
        Not.Dns_Packet.ixx
)
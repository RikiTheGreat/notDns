//
// Created by mahdi on 6/4/24.
//
module;

#include <cstdint>
#include <vector>
#include <memory>

export module Not.Dns:Packet;

export namespace notD {
    struct Header {
        std::uint16_t id{};
        std::uint16_t flags{};
        std::uint16_t num_questions{};
        std::uint16_t num_answers{};
        std::uint16_t num_authorities{};
        std::uint16_t num_additionals{};
    };

    struct Question {
        std::unique_ptr<char[]> name;
        uint16_t type_{};
        uint16_t class_{};
    };

    struct Record {
        std::unique_ptr<char[]> name;
        std::uint16_t type_{};
        std::uint16_t class_{};
        std::uint32_t ttl{};
        std::uint16_t rd_length{};
        std::unique_ptr<char[]> rdata;
    };

    struct Packet {
        Header header;
        std::vector<Question> questions{};
        std::vector<Record> answers{};
        std::vector<Record> authorities{};
        std::vector<Record> additionals{};
    };


    Header parse_header(char const* reply_buf) noexcept;
    Question parse_question(char const* reply_buf) noexcept;
    Record parse_record(char const* reply_buf) noexcept;
    char const* encode_dns_name(const char* domain_name) noexcept;
    std::tuple<char const*, std::size_t> build_query(const char *domain_name, int record_type) noexcept;
    Packet parse_packet(const char* reply_buf, int name_size) noexcept;
    void print_record(std::unique_ptr<char[]> data, std::uint16_t len) noexcept;
    const char *decode_dns_name(const char **ptr, const char *base) noexcept;
    char *decode_compressed_name(const char **ptr, const char *base, std::uint8_t field_len) noexcept;
    bool resolve(const char* domain) noexcept;
}

export void die(const char* e) noexcept;
//
// Created by mahdi on 6/4/24.
//

module;

#include <memory>
#include <cstring>
#include <sstream>
#include <arpa/inet.h>

module Not.Dns;

auto constexpr CLASS_IN = 1;

notD::Header notD::parse_header(char const* reply_buf) noexcept {
    auto h = std::make_unique<notD::Header>();
    notD::Header header;

    std::memcpy(h.get(), reply_buf, sizeof(header));

    header.id = ntohs(h->id);
    header.flags = ntohs(h->flags);
    header.num_questions = ntohs(h->num_questions);
    header.num_answers = ntohs(h->num_answers);
    header.num_authorities = ntohs(h->num_authorities);
    header.num_additionals = ntohs(h->num_additionals);

    return header;
}

notD::Question notD::parse_question(char const* reply_buf) noexcept {
    notD::Question question;

    size_t offset = 0;
    auto ptr = (const char *)reply_buf;
    auto const name = std::string(decode_dns_name(&ptr, reply_buf));

    question.name = std::make_unique<char[]>(name.size());
    std::strncpy(question.name.get(), name.c_str(), name.size());
    auto q = std::make_unique<notD::Question>();
    std::memcpy(&q->type_, reply_buf + name.size() + 2, 2);
    std::memcpy(&q->class_, reply_buf + name.size() + 4, 2);

    question.type_ = ntohs(q->type_);
    question.class_ = ntohs(q->class_);

    return question;
}

notD::Record notD::parse_record(char const *reply_buf) noexcept {
    notD::Record record;

    // TODO fix empty name

    // const char *ptr = (const char *)reply_buf;
    //auto const name =  std::string(decode_dns_name(&ptr, reply_buf));

    // record.name = std::make_unique<char[]>(name.size());
    //  strncpy(record.name.get(), name.c_str(), name.size());

    //size_t pos = name.size() + 8;

    size_t pos = 2;
    std::uint16_t type;
    std::memcpy(&type, reply_buf + pos, sizeof(type));
    record.type_ = ntohs(type);
    pos += sizeof(type);

    std::uint16_t class_;
    std::memcpy(&class_, reply_buf + pos, sizeof(class_));
    record.class_ = ntohs(class_);
    pos += sizeof(class_);

    std::uint32_t ttl;
    std::memcpy(&ttl, reply_buf + pos, sizeof(ttl));
    record.ttl = ntohl(ttl);
    pos += sizeof(ttl);

    std::uint16_t rd_length;
    std::memcpy(&rd_length, reply_buf + pos, sizeof(rd_length));
    record.rd_length = ntohs(rd_length);

    pos += sizeof(rd_length);
    char data[1024] {};
    std::memcpy(data, reply_buf + pos, rd_length);

    record.rdata = std::make_unique<char[]>(rd_length);
    std::strncpy(record.rdata.get(), data, rd_length);
    pos += std::strlen(data);
    return record;
}

char const * notD::encode_dns_name(const char *domain_name) noexcept {
    std::istringstream stream(domain_name);
    std::string segment;
    std::vector<unsigned char> encoded;

    while(std::getline(stream, segment, '.')) {
        if (not segment.empty()) {
            encoded.push_back(static_cast<unsigned char>(segment.length()));
            for (char const c : segment) {
                encoded.push_back(c);
            }
        }
    }

    // Add terminating zero
    encoded.push_back('\0');
    char* out =  (char*) malloc(encoded.size());

    std::memcpy(out, std::string(encoded.begin(), encoded.end()).c_str(), encoded.size());

    return out;
}


std::tuple<char const *, std::size_t> notD::build_query(const char *domain_name, int record_type) noexcept {
    std::uint16_t constexpr id = 0x8298;
    std::uint16_t constexpr flags = 1 << 8;
    notD::Header const header {
        .id = htons(id),
        .flags = htons(flags),
        .num_questions = htons(1)
    };

    notD::Question question {
        .type_ = htons(record_type),
        .class_ = htons(CLASS_IN)
    };

    auto const name = encode_dns_name(domain_name);

    int const name_len = strlen(name) + 1;
    int size = sizeof header + name_len + sizeof question;
    auto *out = static_cast<char *>(malloc(size));
    question.name = std::make_unique<char[]>(name_len);
    std::strncpy(question.name.get(), name, name_len);

    std::memcpy(out + 0, static_cast<const void *>(&header), sizeof header);
    std::memcpy(out + sizeof header, static_cast<const void *> (question.name.get()), name_len);
    std::memcpy(out + sizeof header + name_len, &question.type_, 2);
    std::memcpy(out + sizeof header + name_len + 2, &question.class_, 2);

    delete name;
    return std::make_tuple(out, size);
}

notD::Packet notD::parse_packet(const char *reply_buf, int name_size) noexcept {
        notD::Packet packet;

        auto const header = parse_header(reply_buf);
        packet.header = header;
        std::size_t pos = name_size;

        for(int i{}; i < header.num_questions; ++i) {

            packet.questions.push_back(parse_question(reply_buf + sizeof(header)));
        }

        for(int i{}; i < header.num_answers; ++i) {
            auto ptr = reply_buf + pos + 18;
            packet.answers.push_back(parse_record( ptr));

        }

        // TODO test other records
        for(int i{}; i < header.num_authorities; ++i) {
            auto ptr = reply_buf + pos + 18; // + sizeof answer ???
            packet.authorities.push_back(parse_record(reply_buf + sizeof(header)));
        }

        for(int i{}; i < header.num_additionals; ++i) {
            packet.additionals.push_back(parse_record(reply_buf + sizeof(header)));
        }

        for(int i{}; i < packet.answers.size(); i++)
            print_record(std::move(packet.answers.at(i).rdata), packet.answers.at(i).rd_length);

        return packet;
}

void notD::print_record(std::unique_ptr<char[]> data, std::uint16_t len) noexcept {
    printf("%d", (const uint8_t)data.get()[0]);
    for (int i{1}; i < len; ++i) {
        printf(".%d", (uint8_t const)data.get()[i]);
    }
    printf("\n");
}

const char * notD::decode_dns_name(const char **ptr, const char *base) noexcept {
    char *name = nullptr;
    int length_accumulator = 0;

    while (**ptr != 0) {
        std::uint8_t length = *(*ptr)++;
        if ((length & 0xC0) == 0xC0) {
            const char *part_name = decode_compressed_name(ptr, base, length);
            int part_len = strlen(part_name);
            name = (char*)realloc(name, length_accumulator + part_len + 2);  // +2 for dot and terminating null byte
            if (!name) {
                fprintf(stderr, "Memory allocation failed\n");
                exit(EXIT_FAILURE);
            }
            std::strcpy(name + length_accumulator, part_name);
            length_accumulator += part_len;
            name[length_accumulator++] = '.';
            break;  // After a compression pointer, no more data must be interpreted in this label.
        } else {
            name = (char*) realloc(name, length_accumulator + length + 2);  // +2 for dot and terminating null byte
            if (!name) {
                fprintf(stderr, "Memory allocation failed\n");
                exit(EXIT_FAILURE);
            }
            std::memcpy(name + length_accumulator, *ptr, length);
            *ptr += length;
            length_accumulator += length;
            name[length_accumulator++] = '.';
        }
    }

    if (name) {
        name[length_accumulator - 1] = '\0';  // Replace the last dot with the null character
    } else {
        name = strdup("");  // Just in case there was no content
    }

    return name;
}

char * notD::decode_compressed_name(const char **ptr, const char *base, std::uint8_t field_len) noexcept {
    std::uint8_t next_byte = *(*ptr)++;
    std::uint16_t pointer = ((field_len & 0x3F) << 8) | next_byte;

    // Save the current position and move to the specified offset
    const char *current = *ptr;
    *ptr = base + pointer;

    // Decode the name at the pointer location
    const char *name = decode_dns_name(ptr, base);

    // Restore the original data pointer
    *ptr = current;

    return (char*)name;
}

bool notD::resolve(const char *domain) noexcept {

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
    };
    if (inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr) != 1) {
        fprintf(stderr, "ERROR: can't convert address\n");
        exit(1);
    }

    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd == -1) {
        die("socket");
        return false;
    }

    auto [query, size] = notD::build_query(domain, 1);
    if (sendto(sock_fd, query, size, 0, (const struct sockaddr *)&addr, sizeof addr) == -1)
    {
        die("sendto");
        free((void *)query);
        return false;
    }
    free((void *)query);

    char reply_buf[1024];
    if ((recvfrom(sock_fd, reply_buf, sizeof reply_buf, 0, NULL, NULL)) == -1) {
        die("recvfrom");
        return false;
    }

    notD::parse_packet(reply_buf, strlen(domain));
    close(sock_fd);
    return true;
}


void die(const char* e) noexcept {
    perror(e);
}

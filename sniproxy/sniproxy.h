#pragma once

#include "stdafx.h"
#include "server.h"
#include "Ipep.h"
#include "IPEndPoint.h"
#include "SeekOrigin.h"
#include "Stream.h"
#include "MemoryStream.h"
#include "BinaryReader.h"

class sniproxy final : public std::enable_shared_from_this<sniproxy> {
#pragma pack(push, 1)
    struct tls_hdr {
        Byte                                                    Content_Type;
        UInt16                                                  Version;
        UInt16                                                  Length;
    };
#pragma pack(pop)
    static const int                                            FORWARD_MSS = 65536;

public:
    inline sniproxy(const std::shared_ptr<server>& server, const std::shared_ptr<boost::asio::io_context>& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept
        : handshaked_(false)
        , owner_(server)
        , hosting_(owner_->GetHosting())
        , configuration_(owner_->GetConfiguration())
        , context_(context)
        , local_socket_(socket)
        , remote_socket_(*context)
        , resolver_(*context) {
        boost::system::error_code ec;
        if (configuration_->turbo.lan) {
            socket->set_option(boost::asio::ip::tcp::no_delay(false), ec);
        }
        else {
            socket->set_option(boost::asio::ip::tcp::no_delay(true), ec);
        }
        last_ = hosting_->CurrentMillisec();
    }
    inline ~sniproxy() noexcept {
        close();
    }

public:
    inline void                                                 close() noexcept {
        boost::system::error_code ec_;
        std::shared_ptr<boost::asio::ip::tcp::socket> local_socket = local_socket_;
        if (local_socket) {
            server::closesocket(*local_socket);
        }

        server::closesocket(remote_socket_);
        try {
            resolver_.cancel();
        }
        catch (std::exception&) {}

        std::shared_ptr<boost::asio::deadline_timer> timeout = std::move(timeout_);
        if (timeout) {
            timeout_.reset();
            timeout->cancel(ec_);
        }
        last_ = hosting_->CurrentMillisec();
    }
    inline bool                                                 handshake() noexcept {
        std::shared_ptr<boost::asio::ip::tcp::socket> socket = local_socket_;
        if (!socket || !context_ || !configuration_) {
            return false;
        }

        std::shared_ptr<sniproxy> self = shared_from_this();
        timeout_ = hosting_->Timeout(context_,
            [this, self]() noexcept {
                close();
            }, (uint64_t)configuration_->connect.timeout * 1000);
        if (!timeout_) {
            return false;
        }

        boost::asio::spawn(*context_,
            [self, this](const boost::asio::yield_context& y) noexcept {
                handshaked_ = do_handshake(y);
                if (!handshaked_) {
                    close();
                }
            });
        return true;
    }

private:
    inline UInt16                                               fetch_uint16(Byte*& data) noexcept {
        int h_ = (Byte)*data++;
        int l_ = (Byte)*data++;
        return (h_ << 8) | (l_);
    }
    inline std::string                                          fetch_sniaddr(size_t tls_payload) noexcept {
        Byte* data = (Byte*)local_socket_buf_;
        if (*data++ != 0x01) { // Handshake Type: Client Hello (1)
            return "";
        }

        int Length = std::max<int>(0, data[0] << 16 | data[1] << 8 | data[2]);
        data += 3;

        if ((Length + 4) != tls_payload) {
            return "";
        }

        // Skip Version
        data += 2;

        // Skip Random
        data += 32;

        // Skip Session ID
        Byte Session_ID_Length = std::max<int>((Byte)0, *data++);
        data += Session_ID_Length;

        // Skip Cipher Suites
        int Cipher_Suites_Length = std::max<int>(0, fetch_uint16(data));
        data += Cipher_Suites_Length;

        // Skip Compression Methods Length
        int Compression_Methods_Length = *data++;
        data += Compression_Methods_Length;

        // Extensions Length
        int Extensions_Length = std::max<int>(0, fetch_uint16(data));
        Byte* Extensions_End = data + Extensions_Length;
        while (data < Extensions_End) {
            int Extension_Type = fetch_uint16(data);
            int Extension_Length = std::max<int>(0, fetch_uint16(data));
            if (Extension_Type == 0x0000) { // RFC4366/6066(Server Name Indication extension)
                int Server_Name_list_length = std::max<int>(0, fetch_uint16(data));
                if ((data + Server_Name_list_length) >= Extensions_End) {
                    break;
                }

                int Server_Name_Type = *data++;
                if (Server_Name_Type != 0x00) { // RFC6066 NameType::host_name(0)
                    data += 2;
                    continue;
                }

                int Server_Name_length = std::max<int>(0, fetch_uint16(data));
                if ((data + Server_Name_length) > Extensions_End) {
                    break;
                }
                return std::string((char*)data, 0, Server_Name_length);
            }
            else {
                data += Extension_Length;
            }
        }
        return "";
    }
    inline bool                                                 do_handshake(const boost::asio::yield_context& y) noexcept {
        const int header_size_ = sizeof(struct tls_hdr);
        if (!network::asio::async_read(*local_socket_, boost::asio::buffer(local_socket_buf_, header_size_), y)) {
            return false;
        }

        MemoryStream messages_;
        messages_.Write(local_socket_buf_, 0, header_size_);

        if (do_tlsvd_handshake(y, messages_)) {
            return true;
        }

        if (!network::asio::async_read(*local_socket_, boost::asio::buffer(local_socket_buf_ + header_size_, 3), y)) {
            return false;
        }

        messages_.Write(local_socket_buf_, header_size_, 3);
        if (!be_http(local_socket_buf_)) {
            return false;
        }

        return do_httpd_handshake(y, messages_);
    }
    inline bool                                                 socket_is_open() noexcept {
        if (!local_socket_ || !local_socket_->is_open()) {
            return false;
        }
        return remote_socket_.is_open();
    }
    inline bool                                                 local_to_remote() noexcept {
        bool available_ = socket_is_open();
        if (!available_) {
            return false;
        }

        std::shared_ptr<sniproxy> self = shared_from_this();
        local_socket_->async_read_some(boost::asio::buffer(local_socket_buf_, FORWARD_MSS),
            [self, this](const boost::system::error_code& ec, uint32_t sz) noexcept {
                int by = std::max<int>(-1, ec ? -1 : sz);
                if (by < 1) {
                    close();
                    return;
                }

                boost::asio::async_write(remote_socket_, boost::asio::buffer(local_socket_buf_, by),
                    [self, this](const boost::system::error_code& ec, uint32_t sz) noexcept {
                        if (ec || !local_to_remote()) {
                            close();
                            return;
                        }

                        last_ = hosting_->CurrentMillisec();
                    });
                last_ = hosting_->CurrentMillisec();
            });
        return true;
    }
    inline bool                                                 remote_to_local() noexcept {
        bool available_ = socket_is_open();
        if (!available_) {
            return false;
        }

        std::shared_ptr<sniproxy> self = shared_from_this();
        remote_socket_.async_read_some(boost::asio::buffer(remote_socket_buf_, FORWARD_MSS),
            [self, this](const boost::system::error_code& ec, uint32_t sz) noexcept {
                int by = std::max<int>(-1, ec ? -1 : sz);
                if (by < 1) {
                    close();
                    return;
                }

                boost::asio::async_write(*local_socket_.get(), boost::asio::buffer(remote_socket_buf_, by),
                    [self, this](const boost::system::error_code& ec, uint32_t sz) noexcept {
                        if (ec || !remote_to_local()) {
                            close();
                            return;
                        }

                        last_ = hosting_->CurrentMillisec();
                    });
                last_ = hosting_->CurrentMillisec();
            });
        return true;
    }

private:
    inline static bool                                          be_http(const void* p) noexcept {
        char* data = (char*)p;
        if (!data) {
            return false;
        }
        return
            strncasecmp(data, "GET ", 4) == 0 ||
            strncasecmp(data, "HEAD ", 5) == 0 ||
            strncasecmp(data, "POST ", 5) == 0 ||
            strncasecmp(data, "PUT ", 4) == 0 ||
            strncasecmp(data, "DELETE ", 7) == 0 ||
            strncasecmp(data, "CONNECT ", 8) == 0 ||
            strncasecmp(data, "TRACE ", 6) == 0 ||
            strncasecmp(data, "PATCH ", 6) == 0;
    }
    inline static bool                                          be_host(std::string host, std::string domain) noexcept {
        if (host.empty() || domain.empty()) {
            return false;
        }

        domain = ToLower(domain);
        host = ToLower(host);

        // Direct hit
        if (domain == host) {
            return true;
        }

        // Segment hit
        std::vector<std::string> lables;
        if (Tokenize<std::string>(domain, lables, ".") < 3) {
            return false;
        }

        size_t lables_count = lables.size();
        for (size_t i = 0; i < lables_count; i++) {
            const std::string& label = lables[i];
            if (label.empty()) {
                return false;
            }
        }

        for (size_t i = 1, l = lables_count - 1; i < l; i++) {
            std::string next;
            for (size_t j = i; j < lables_count; j++) {
                if (next.empty()) {
                    next += lables[j];
                }
                else {
                    next += "." + lables[j];
                }
            }
            if (next == host) {
                return true;
            }
        }
        return false;
    }
    inline bool                                                 do_tlsvd_handshake(const boost::asio::yield_context& y, MemoryStream& messages_) noexcept {
        struct tls_hdr* hdr = (struct tls_hdr*)local_socket_buf_;
        if (hdr->Content_Type != 0x16) { // Handshake
            return false;
        }

        size_t tls_payload = ntohs(hdr->Length);
        if (!tls_payload) {
            return false;
        }

        if (!network::asio::async_read(*local_socket_, boost::asio::buffer(local_socket_buf_, tls_payload), y)) {
            return false;
        }
        else {
            messages_.Write(local_socket_buf_, 0, tls_payload);
        }

        std::string hostname_ = fetch_sniaddr(tls_payload);
        IPEndPoint reverse_server_ = Ipep::GetEndPoint(configuration_->reverse_proxy.http_ssl);
        return do_connect_and_forward_to_host(y, hostname_, 443, reverse_server_, messages_);
    }
    inline bool                                                 do_httpd_handshake(const boost::asio::yield_context& y, MemoryStream& messages_) noexcept {
        if (!do_read_http_request_headers(y, messages_)) {
            return false;
        }

        int port_;
        std::string hostname_;
        if (!do_httpd_handshake_host_trim(messages_, hostname_, port_)) {
            return false;
        }

        IPEndPoint reverse_server_ = Ipep::GetEndPoint(configuration_->reverse_proxy.http);
        return do_connect_and_forward_to_host(y, hostname_, port_, reverse_server_, messages_);
    }
    inline bool                                                 do_httpd_handshake_host_trim(MemoryStream& messages_, std::string& host, int& port) noexcept {
        port = 80;
        host = do_httpd_handshake_host(messages_);
        if (host.empty()) {
            return false;
        }

        host = RTrim(LTrim(host));
        if (host.empty()) {
            return false;
        }

        std::size_t index = host.find(":");
        if (index == std::string::npos) {
            return true;
        }

        std::string hoststr = host.substr(0, index);
        if (hoststr.empty()) {
            return false;
        }

        std::string portstr = host.substr(index + 1);
        if (portstr.empty()) {
            return false;
        }

        portstr = RTrim(LTrim(portstr));
        if (portstr.empty()) {
            return false;
        }

        port = atoi(portstr.data());
        if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
            return false;
        }

        host = std::move(hoststr);
        return true;
    }
    inline std::string                                          do_httpd_handshake_host(MemoryStream& messages_) noexcept {
        int headers_size = messages_.GetPosition();
        if (headers_size < 4) {
            return "";
        }

        std::vector<std::string> headers;
        if (Tokenize<std::string>(std::string((char*)messages_.GetBuffer().get(), headers_size), headers, "\r\n") < 1) {
            return "";
        }

        // GET / HTTP/1.1
        std::vector<std::string> protocols;
        if (Tokenize<std::string>(headers[0], protocols, " ") < 3) {
            return "";
        }
        else {
            std::string protocol = ToUpper(protocols[2]);
            if (protocol != "HTTP/1.0" &&
                protocol != "HTTP/1.1" &&
                protocol != "HTTP/2.0") {
                return "";
            }

            const std::string& url_or_path = protocols[1];
            if (url_or_path.empty()) {
                return "";
            }

            if (url_or_path[0] != '/') {
                std::string url = ToLower(url);
                do {
                    std::size_t leftIndex = url.find("://");
                    if (leftIndex == std::string::npos) {
                        break;
                    }

                    std::string schema = url.substr(0, leftIndex);
                    if (schema != "http") {
                        break;
                    }
                    else {
                        leftIndex += 3;
                    }

                    std::size_t nextIndex = url.find("/", leftIndex);
                    if (nextIndex == std::string::npos) {
                        return "";
                    }

                    std::size_t hostCount = nextIndex - leftIndex;
                    if (!hostCount) {
                        return "";
                    }

                    return protocols[1].substr(leftIndex, hostCount);
                } while (0);
            }
        }

        for (size_t i = 1, header_count = headers.size(); i < header_count; i++) {
            const std::string& header = headers[i];
            if (header.empty()) {
                return "";
            }

            std::size_t leftIndex = header.find(": ");
            if (!leftIndex || leftIndex == std::string::npos) {
                return "";
            }

            std::size_t rightIndex = leftIndex + 2;
            if (rightIndex > header.size()) {
                return "";
            }

            std::string key = ToUpper(header.substr(0, leftIndex));
            if (key == "HOST") {
                return header.substr(rightIndex);
            }
        }
        return "";
    }
    inline bool                                                 do_read_http_request_headers(const boost::asio::yield_context& y, MemoryStream& messages_) noexcept {
        boost::system::error_code ec_;
        boost::asio::streambuf response_;
        size_t length_;
        try {
            length_ = boost::asio::async_read_until(*local_socket_, response_, "\r\n\r\n", y[ec_]);
            if (ec_) {
                return false;
            }

            if (!length_) {
                return false;
            }
        }
        catch (std::exception&) {
            return false;
        }

        boost::asio::const_buffers_1 buff_ = response_.data();
        messages_.Write(buff_.data(), 0, length_);
        return true;
    }
    inline bool                                                 do_connect_and_forward_to_host(const boost::asio::yield_context& y, const std::string hostname_, int port_, const IPEndPoint& reverse_server_, MemoryStream& messages_) noexcept {
        if (hostname_.empty() ||
            port_ <= IPEndPoint::MinPort ||
            port_ > IPEndPoint::MaxPort) {
            return false;
        }

        boost::system::error_code ec_;
        boost::asio::ip::address address_;
        boost::asio::ip::tcp::endpoint remoteEP_;

        if (be_host(configuration_->reverse_proxy.host, hostname_)) {
            if (IPEndPoint::IsInvalid(reverse_server_)) {
                return false;
            }

            if (reverse_server_.Port <= IPEndPoint::MinPort || reverse_server_.Port > IPEndPoint::MinPort) {
                return false;
            }
            remoteEP_ = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(reverse_server_);
        }
        else {
            address_ = boost::asio::ip::address::from_string(hostname_.data(), ec_);
            if (ec_) {
                address_ = IPEndPoint::GetAddressByHostName(resolver_, hostname_, IPEndPoint::MinPort, y).address();
            }

            if (address_.is_unspecified() || address_.is_loopback() || address_.is_multicast()) {
                return false;
            }
            remoteEP_ = boost::asio::ip::tcp::endpoint(address_, port_);
        }

        if (address_.is_v4()) {
            remote_socket_.open(boost::asio::ip::tcp::v4(), ec_);
        }
        elif(address_.is_v6()) {
            remote_socket_.open(boost::asio::ip::tcp::v6(), ec_);
        }
        else {
            return false;
        }

        if (ec_) {
            return false;
        }

        if (configuration_->fast_open) {
            remote_socket_.set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(true), ec_);
        }

        if (configuration_->turbo.wan) {
            remote_socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec_);
        }

        int handle_ = remote_socket_.native_handle();
        server::SetTypeOfService(handle_);
        server::SetSignalPipeline(handle_, false);
        server::SetDontFragment(handle_, false);
        server::ReuseSocketAddress(handle_, false);

        // [CONNECT]SSL VPN
        if (network::asio::async_connect(remote_socket_, remoteEP_, y)) {
            return false;
        }

        std::shared_ptr<Byte> buff_ = messages_.GetBuffer();
        if (!network::asio::async_write(remote_socket_, boost::asio::buffer(buff_.get(), messages_.GetPosition()), y)) {
            return false;
        }
        return local_to_remote() && remote_to_local();
    }

private:
    bool                                                        handshaked_;
    std::shared_ptr<server>                                     owner_;
    std::shared_ptr<Hosting>                                    hosting_;
    std::shared_ptr<server_configuration>                       configuration_;
    std::shared_ptr<boost::asio::io_context>                    context_;
    std::shared_ptr<boost::asio::ip::tcp::socket>               local_socket_;
    boost::asio::ip::tcp::socket                                remote_socket_;
    boost::asio::ip::tcp::resolver                              resolver_;
    uint64_t                                                    last_;
    std::shared_ptr<boost::asio::deadline_timer>                timeout_;
    char                                                        local_socket_buf_[FORWARD_MSS];
    char                                                        remote_socket_buf_[FORWARD_MSS];
};
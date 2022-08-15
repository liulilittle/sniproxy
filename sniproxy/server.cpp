#include "server.h"
#include "sniproxy.h"

bool server::Run(std::function<void()> running) noexcept {
    std::shared_ptr<boost::asio::io_context> context_;
    std::shared_ptr<boost::asio::io_context> previous_;
    do {
        std::shared_ptr<server_configuration> configuration_ = GetConfiguration();
        if (!configuration_) {
            return false;
        }

        std::shared_ptr<Hosting> hosting_ = server_hosting();
        if (!hosting_) {
            return false;
        }

        MutexScope scope(lockobj_);
        context_ = make_shared_object<boost::asio::io_context>();
        if (!context_) {
            return false;
        }

        previous_ = hosting_->ExchangeDefault(context_);
        if (!hosting_->OpenTimeout()) {
            return false;
        }

        if (!OpenAcceptor(ACCEPT_SOCKET_ORIGIN::ACCEPT_SOCKET_ORIGIN_HTTP, configuration_->listen.http)) {
            return false;
        }

        if (!OpenAcceptor(ACCEPT_SOCKET_ORIGIN::ACCEPT_SOCKET_ORIGIN_HTTP_SSL, configuration_->listen.http_ssl)) {
            return false;
        }

        if (running) {
            context_->post(std::move(running));
        }
    } while (0);
    boost::system::error_code ec_;
    boost::asio::io_context::work work_(*context_);
    context_->run(ec_);
    hosting_->CompareExchangeDefault(previous_, context_);
    return true;
}

bool server::OpenAcceptor(ACCEPT_SOCKET_ORIGIN origin, int& listen) noexcept {
    if ((int)origin < ACCEPT_SOCKET_ORIGIN::ACCEPT_SOCKET_ORIGIN_MIN_COUNT || (int)origin >= ACCEPT_SOCKET_ORIGIN::ACCEPT_SOCKET_ORIGIN_MAX_COUNT) {
        return false;
    }
    
    std::shared_ptr<boost::asio::io_context> context_ = hosting_->GetDefault();
    if (!context_) {
        return false;
    }

    std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor = acceptor_[(int)origin];
    if (acceptor) {
        return false;
    }

    acceptor = make_shared_object<boost::asio::ip::tcp::acceptor>(*context_);
    if (!acceptor) {
        return false;
    }

    boost::system::error_code ec_;
    acceptor->open(boost::asio::ip::tcp::v6(), ec_);
    if (ec_) {
        return false;
    }

    std::shared_ptr<server_configuration> configuration_ = GetConfiguration();
    if (configuration_->fast_open) {
        acceptor->set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(true), ec_);
    }

    if (configuration_->turbo.lan) {
        acceptor->set_option(boost::asio::ip::tcp::no_delay(true), ec_);
    }

    int handle_ = acceptor->native_handle();
    server::setsockopt(handle_, false);
    server::SetTypeOfService(handle_);
    server::SetSignalPipeline(handle_, false);
    server::SetDontFragment(handle_, false);
    server::ReuseSocketAddress(handle_, true);

    acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec_);
    if (ec_) {
        return false;
    }

    if (listen < IPEndPoint::MinPort || listen > IPEndPoint::MaxPort) {
        listen = IPEndPoint::MinPort;
    }

    boost::asio::ip::address_v6 address_ = boost::asio::ip::address_v6::any();
    acceptor->bind(boost::asio::ip::tcp::endpoint(address_, listen), ec_);
    if (ec_) {
        if (listen != IPEndPoint::MinPort) {
            acceptor->bind(boost::asio::ip::tcp::endpoint(address_, IPEndPoint::MinPort), ec_);
            if (ec_) {
                return false;
            }
        }
    }

    boost::asio::ip::tcp::endpoint& localEP = localEP_[(int)origin];
    localEP = acceptor->local_endpoint(ec_);
    if (ec_) {
        return false;
    }
    else {
        listen = localEP.port();
        localEP = boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v6::loopback(), listen);
    }

    acceptor->listen(configuration_->backlog, ec_);
    if (ec_) {
        return false;
    }
    return AcceptSocket(origin);
}

bool server::AcceptSocket(ACCEPT_SOCKET_ORIGIN origin) noexcept {
    if ((int)origin < ACCEPT_SOCKET_ORIGIN::ACCEPT_SOCKET_ORIGIN_MIN_COUNT || (int)origin >= ACCEPT_SOCKET_ORIGIN::ACCEPT_SOCKET_ORIGIN_MAX_COUNT) {
        return false;
    }

    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor = acceptor_[(int)origin];
    if (!acceptor || !acceptor->is_open()) {
        return false;
    }

    std::shared_ptr<server> server_ = GetPtr();
    std::shared_ptr<boost::asio::io_context> context_ = hosting_->GetContext();
    std::shared_ptr<boost::asio::ip::tcp::socket> socket_ = make_shared_object<boost::asio::ip::tcp::socket>(*context_);
    acceptor->async_accept(*socket_,
        [origin, server_, this, context_, socket_](boost::system::error_code ec_) noexcept {
            bool success = false;
            do {
                if (ec_ == boost::system::errc::connection_aborted) { /* ECONNABORTED */
                    break;
                }
                elif(ec_) {
                    assert(false);
                    abort();
                    return;
                }

                int handle_ = socket_->native_handle();
                server::setsockopt(handle_, false);
                server::SetTypeOfService(handle_);
                server::SetSignalPipeline(handle_, false);
                server::SetDontFragment(handle_, false);
                server::ReuseSocketAddress(handle_, true);

                std::shared_ptr<server_configuration> configuration_ = GetConfiguration();
                if (configuration_->turbo.lan) {
                    socket_->set_option(boost::asio::ip::tcp::no_delay(true), ec_);
                    if (ec_) {
                        break;
                    }
                }

                success = AcceptSocket(origin, context_, socket_);
            } while (0);
            if (!success) {
                socket_->shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec_);
                socket_->close(ec_);
            }
            AcceptSocket(origin);
        });
    return true;
}

bool server::AcceptSocket(ACCEPT_SOCKET_ORIGIN origin, const std::shared_ptr<boost::asio::io_context>& context_, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket_) noexcept {
    std::shared_ptr<server> server_ = GetPtr();
    if(origin == ACCEPT_SOCKET_ORIGIN::ACCEPT_SOCKET_ORIGIN_HTTP) {
        std::shared_ptr<sniproxy> session_ = make_shared_object<sniproxy>(server_, context_, socket_);
        return session_->handshake();
    }
    elif(origin == ACCEPT_SOCKET_ORIGIN::ACCEPT_SOCKET_ORIGIN_HTTP_SSL) {
        std::shared_ptr<sniproxy> session_ = make_shared_object<sniproxy>(server_, context_, socket_);
        return session_->handshake();
    }
    else {
        return false;
    }
}

void server::closesocket(boost::asio::ip::tcp::acceptor& s) noexcept {
    if (s.is_open()) {
        boost::system::error_code ec;
        s.close(ec);
    }
}

void server::closesocket(boost::asio::ip::tcp::socket& s) noexcept {
    if (s.is_open()) {
        boost::system::error_code ec;
        s.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
        s.close(ec);
    }
}

void server::setsockopt(int sockfd, bool v4_or_v6) noexcept {
    if (sockfd != -1) {
        uint8_t tos = 0x68;
        if (v4_or_v6) {
            ::setsockopt(sockfd, SOL_IP, IP_TOS, (char*)&tos, sizeof(tos));

#ifdef _WIN32
            int dont_frag = 0;
            ::setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAGMENT, (char*)&dont_frag, sizeof(dont_frag));
#elif IP_MTU_DISCOVER
            int dont_frag = IP_PMTUDISC_WANT;
            ::setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &dont_frag, sizeof(dont_frag));
#endif
        }
        else {
            ::setsockopt(sockfd, SOL_IPV6, IP_TOS, (char*)&tos, sizeof(tos));

#ifdef _WIN32
            int dont_frag = 0;
            ::setsockopt(sockfd, IPPROTO_IPV6, IP_DONTFRAGMENT, (char*)&dont_frag, sizeof(dont_frag));
#elif IPV6_MTU_DISCOVER
            int dont_frag = IPV6_PMTUDISC_WANT;
            ::setsockopt(sockfd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &dont_frag, sizeof(dont_frag));
#endif
        }
#ifdef SO_NOSIGPIPE
        int no_sigpipe = 1;
        ::setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe));
#endif
    }
}

server_configuration::server_configuration() noexcept {
    clear();
}

void server_configuration::clear() noexcept {
    concurrent = Hosting::GetMaxConcurrency();
    backlog = 511;
    fast_open = false;
    turbo.lan = false;
    turbo.wan = false;
    listen.http = 80;
    listen.http_ssl = 443;
    reverse_proxy.host.clear();
    reverse_proxy.http.clear();
    reverse_proxy.http_ssl.clear();
    connect.timeout = 5;
}
#pragma once

#include "stdafx.h"
#include "Hosting.h"

class server_configuration final {
public:
    int                                                             concurrent;
    int                                                             backlog;
    bool                                                            fast_open;
    struct {
        bool                                                        lan;
        bool                                                        wan;
    }                                                               turbo;
    struct {
        int                                                         http;
        int                                                         http_ssl;
    }                                                               listen;
    struct {
        std::string                                                 host;
        std::string                                                 http;
        std::string                                                 http_ssl;
    }                                                               reverse_proxy;
    struct {
        int                                                         timeout;
    }                                                               connect;

public:
    server_configuration() noexcept;

public:
    void                                                            clear() noexcept;
};

class server final : public std::enable_shared_from_this<server> {
public:
    typedef std::shared_ptr<server>                                 Ptr;
    typedef std::mutex                                              Mutex;
    typedef std::lock_guard<Mutex>                                  MutexScope;

public:
    inline server(const std::shared_ptr<Hosting>& hosting, const std::shared_ptr<server_configuration>& configuration) noexcept
        : hosting_(hosting)
        , configuration_(configuration) {

    }

public:
    inline Ptr                                                      GetPtr() noexcept {
        return shared_from_this();
    }
    inline const std::shared_ptr<Hosting>&                          GetHosting() const noexcept {
        return hosting_;
    }
    inline const std::shared_ptr<server_configuration>&             GetConfiguration() const noexcept {
        return configuration_;
    }

public:
    typedef enum {
        ACCEPT_SOCKET_ORIGIN_MIN_COUNT,
        ACCEPT_SOCKET_ORIGIN_HTTP = ACCEPT_SOCKET_ORIGIN_MIN_COUNT,
        ACCEPT_SOCKET_ORIGIN_HTTP_SSL,
        ACCEPT_SOCKET_ORIGIN_MAX_COUNT,
    } ACCEPT_SOCKET_ORIGIN;
    inline const boost::asio::ip::tcp::endpoint                     GetLocalEndPoint(ACCEPT_SOCKET_ORIGIN origin) noexcept {
        if ((int)origin < ACCEPT_SOCKET_ORIGIN::ACCEPT_SOCKET_ORIGIN_MIN_COUNT ||
            (int)origin >= ACCEPT_SOCKET_ORIGIN::ACCEPT_SOCKET_ORIGIN_MAX_COUNT) {
            return boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v6::any(), 0);
        }
        return localEP_[(int)origin];
    }
    bool                                                            Run(std::function<void()> running) noexcept;
    inline static bool                                              SetTypeOfService(int fd, int tos = ~0) noexcept {
        if (fd == -1) {
            return false;
        }

        if (tos < 0) {
            tos = 0x68; // FLASH
        }

        Byte b = tos;
        return ::setsockopt(fd, SOL_IP, IP_TOS, (char*)&b, sizeof(b)) == 0;
    }
    inline static bool                                              SetSignalPipeline(int fd, bool sigpipe) noexcept {
        if (fd == -1) {
            return false;
        }

        int err = 0;
#ifdef SO_NOSIGPIPE
        int opt = sigpipe ? 0 : 1;
        err = ::setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, (char*)&opt, sizeof(opt));
#endif
        return err == 0;
    }
    inline static bool                                              SetDontFragment(int fd, bool dontFragment) noexcept {
        if (fd == -1) {
            return false;
        }

        int err = 0;
#ifdef _WIN32 
        int val = dontFragment ? 1 : 0;
        err = ::setsockopt(fd, IPPROTO_IP, IP_DONTFRAGMENT, (char*)&val, sizeof(val));
#elif IP_MTU_DISCOVER
        int val = dontFragment ? IP_PMTUDISC_DO : IP_PMTUDISC_WANT;
        err = ::setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, (char*)&val, sizeof(val));
#endif
        return err == 0;
    }
    inline static bool                                              ReuseSocketAddress(int fd, bool reuse) noexcept {
        if (fd == -1) {
            return false;
        }
        int flag = reuse ? 1 : 0;
        return ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&flag, sizeof(flag)) == 0;
    }

public:
    static void                                                     setsockopt(int sockfd, bool v4_or_v6) noexcept;
    static void                                                     closesocket(boost::asio::ip::tcp::socket& s) noexcept;
    static void                                                     closesocket(boost::asio::ip::tcp::acceptor& s) noexcept;

private:
    bool                                                            AcceptSocket(ACCEPT_SOCKET_ORIGIN origin) noexcept;
    bool                                                            AcceptSocket(ACCEPT_SOCKET_ORIGIN origin, const std::shared_ptr<boost::asio::io_context>& context_, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket_) noexcept;
    bool                                                            OpenAcceptor(ACCEPT_SOCKET_ORIGIN origin, int& listen) noexcept;

private:
    Mutex                                                           lockobj_;
    std::shared_ptr<Hosting>                                        hosting_;
    std::shared_ptr<server_configuration>                           configuration_;
    boost::asio::ip::tcp::endpoint                                  localEP_[ACCEPT_SOCKET_ORIGIN_MAX_COUNT];
    std::shared_ptr<boost::asio::ip::tcp::acceptor>                 acceptor_[ACCEPT_SOCKET_ORIGIN_MAX_COUNT];
};
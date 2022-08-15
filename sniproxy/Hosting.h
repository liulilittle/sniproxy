#pragma once

#include "stdafx.h"

class Hosting final : public std::enable_shared_from_this<Hosting> {
    typedef std::shared_ptr<boost::asio::io_context>            ContextPtr;
    typedef std::mutex                                          Mutex;
    typedef std::lock_guard<Mutex>                              MutexScope;
    typedef std::list<ContextPtr>                               ContextList;

public:
    inline Hosting() noexcept
        : Hosting(0) {

    }
    inline Hosting(int concurrent) noexcept
        : now_(0) {
        if (concurrent < 1) {
            concurrent = GetMaxConcurrency();
        }
        concurrent_ = concurrent;
    }

public:
    void                                                        Run() noexcept;
    std::shared_ptr<boost::asio::io_context>                    GetContext() noexcept;

public:
    inline const std::shared_ptr<boost::asio::io_context>&      GetDefault() const noexcept {
        return def_;
    }
    inline std::shared_ptr<boost::asio::io_context>             ExchangeDefault(const std::shared_ptr<boost::asio::io_context>& context_) noexcept {
        MutexScope scope_(lockobj_);
        std::shared_ptr<boost::asio::io_context> current_ = std::move(def_);
        def_ = context_;
        return std::move(current_);
    }
    inline std::shared_ptr<boost::asio::io_context>             CompareExchangeDefault(const std::shared_ptr<boost::asio::io_context>& context_, const std::shared_ptr<boost::asio::io_context>& comparand_) noexcept {
        MutexScope scope_(lockobj_);
        std::shared_ptr<boost::asio::io_context> current_ = def_;
        if (context_ != comparand_) {
            if (current_ == comparand_) {
                def_ = context_;
            }
        }
        return std::move(current_);
    }

public:
    bool                                                        OpenTimeout() noexcept;
    void                                                        Attach(const std::shared_ptr<boost::asio::io_context>& context_) noexcept;
    void                                                        Unattach(const std::shared_ptr<boost::asio::io_context>& context_) noexcept;

public:
    inline uint64_t                                             CurrentMillisec() noexcept {
        return now_;
    }
    inline std::shared_ptr<Hosting>                             GetPtr() noexcept {
        return shared_from_this();
    }
    inline int                                                  GetConcurrency() noexcept {
        return concurrent_;
    }
    inline static int                                           GetMaxConcurrency() noexcept {
        int concurrent = std::thread::hardware_concurrency();
        if (concurrent < 1) {
            concurrent = 1;
        }
        return concurrent;
    }

public:
    template<typename TimeoutHandler>
    inline std::shared_ptr<boost::asio::deadline_timer>         Timeout(const BOOST_ASIO_MOVE_ARG(TimeoutHandler) handler, int timeout) noexcept {
        std::shared_ptr<boost::asio::io_context> context_ = GetDefault();
        if (!context_) {
            context_ = GetContext();
        }
        return Timeout<TimeoutHandler>(context_, forward0f(handler), timeout);
    }
    template<typename TimeoutHandler>
    inline static std::shared_ptr<boost::asio::deadline_timer>  Timeout(const std::shared_ptr<boost::asio::io_context>& context_, const BOOST_ASIO_MOVE_ARG(TimeoutHandler) handler, int timeout) noexcept {
        if (timeout < 1) {
            handler();
            return NULL;
        }

        if (!context_) {
            return NULL;
        }

        class AsyncWaitTimeoutHandler final {
        public:
            std::shared_ptr<boost::asio::deadline_timer>        timeout_;
            TimeoutHandler                                      handler_;

        public:
            inline AsyncWaitTimeoutHandler(const AsyncWaitTimeoutHandler&& other) noexcept
                : handler_(std::move(constantof(other.handler_)))
                , timeout_(std::move(constantof(other.timeout_))) {

            }
            inline AsyncWaitTimeoutHandler(const std::shared_ptr<boost::asio::deadline_timer>& timeout, TimeoutHandler&& handler) noexcept
                : timeout_(timeout)
                , handler_(std::move(handler)) {

            }

        public:
            inline void operator()(const boost::system::error_code& ec) noexcept {
                if (!ec) {
                    handler_();
                }
            }
        };

        std::shared_ptr<boost::asio::deadline_timer> timeout_ = make_shared_object<boost::asio::deadline_timer>(*context_);
        if (!timeout_) {
            return NULL;
        }

        AsyncWaitTimeoutHandler completion_(timeout_, BOOST_ASIO_MOVE_CAST(TimeoutHandler)(constantof(handler)));
        timeout_->expires_from_now(boost::posix_time::milliseconds(timeout));
        timeout_->async_wait(BOOST_ASIO_MOVE_CAST(AsyncWaitTimeoutHandler)(completion_));
        return timeout_;
    }

private:
    bool                                                        WaitTimeout() noexcept;
    std::shared_ptr<boost::asio::io_context>                    AllocContext() noexcept;

private:
    int                                                         concurrent_;
    uint64_t                                                    now_;
    Mutex                                                       lockobj_;
    std::shared_ptr<boost::asio::io_context>                    def_;
    std::shared_ptr<boost::asio::deadline_timer>                timeout_;
    ContextList                                                 contexts_;
};

std::shared_ptr<Hosting>&                                       server_hosting() noexcept;
#include "stdafx.h"
#include "Hosting.h"

static std::shared_ptr<Hosting> hosting_;

std::shared_ptr<Hosting>& server_hosting() noexcept {
    return hosting_;
}

void Hosting::Run() noexcept {
    MutexScope scope_(lockobj_);
    for (size_t i = contexts_.size(), l = concurrent_; i < l; i++) {
        std::shared_ptr<boost::asio::io_context> context_ = AllocContext();
        if (context_) {
            contexts_.push_back(context_);
        }
    }
}

bool Hosting::OpenTimeout() noexcept {
    MutexScope scope_(lockobj_);
    if (timeout_) {
        return true;
    }

    std::shared_ptr<boost::asio::io_context> context_ = def_;
    if (!context_) {
        return false;
    }

    timeout_ = make_shared_object<boost::asio::deadline_timer>(*context_);
    if (!timeout_) {
        return false;
    }

    return WaitTimeout();
}

bool Hosting::WaitTimeout() noexcept {
    const std::shared_ptr<Hosting> self = GetPtr();
    const std::shared_ptr<boost::asio::deadline_timer> timeout = timeout_;
    if (!timeout) {
        return false;
    }

    const static uint64_t ANY_WAIT_TICK_TIMEOUT = 10;
    timeout->expires_from_now(boost::posix_time::milliseconds(ANY_WAIT_TICK_TIMEOUT));
    timeout->async_wait(
        [this, self, timeout](const boost::system::error_code& ec) noexcept {
            now_ += ANY_WAIT_TICK_TIMEOUT;
            WaitTimeout();
        });
    return true;
}

std::shared_ptr<boost::asio::io_context> Hosting::AllocContext() noexcept {
    const std::shared_ptr<boost::asio::io_context> context_ = make_shared_object<boost::asio::io_context>();
    const auto dowork_ = [context_] {
        SetThreadPriorityToMaxLevel();

        boost::system::error_code ec_;
        boost::asio::io_context::work work_(*context_);
        context_->run(ec_);
    };
    std::thread(std::move(dowork_)).detach();
    return context_;
}

std::shared_ptr<boost::asio::io_context> Hosting::GetContext() noexcept {
    MutexScope scope_(lockobj_);
    ContextList::iterator tail = contexts_.begin();
    ContextList::iterator endl = contexts_.end();
    if (tail == endl) {
        return NULL;
    }
    if (concurrent_ == 1) {
        return *tail;
    }
    else {
        std::shared_ptr<boost::asio::io_context> context_ = *tail;
        contexts_.erase(tail);
        contexts_.push_back(context_);
        return std::move(context_);
    }
}

void Hosting::Attach(const std::shared_ptr<boost::asio::io_context>& context_) noexcept {
    if (context_) {
        MutexScope scope_(lockobj_);
        contexts_.push_back(context_);
    }
}

void Hosting::Unattach(const std::shared_ptr<boost::asio::io_context>& context_) noexcept {
    if (context_) {
        MutexScope scope_(lockobj_);
        ContextList::iterator tail = contexts_.begin();
        ContextList::iterator endl = contexts_.end();
        for (; tail != endl; tail++) {
            if (context_ == *tail) {
                contexts_.erase(tail);
                break;
            }
        }
    }
}
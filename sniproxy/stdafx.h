#pragma once

#include <stdio.h>

#ifndef BOOST_BEAST_VERSION_HPP
#define BOOST_BEAST_VERSION_HPP

#include <boost/beast/core/detail/config.hpp>
#include <boost/config.hpp>

/*  BOOST_BEAST_VERSION

    Identifies the API version of Beast.

    This is a simple integer that is incremented by one every
    time a set of code changes is merged to the develop branch.
*/
#define BOOST_BEAST_VERSION 322
#define BOOST_BEAST_VERSION_STRING "ppp"
#endif

#include <boost/function.hpp>
#include <boost/asio.hpp>
#if !defined(NCOROUTINE)
#include <boost/asio/spawn.hpp>
#endif
#include <boost/date_time/posix_time/posix_time.hpp>

#ifdef _WIN32
namespace boost { // boost::asio::posix::stream_descriptor
    namespace asio {
        namespace posix {
            typedef boost::asio::windows::stream_handle stream_descriptor;
        }
    }
}

#include <io.h>
#include <WinSock2.h>
#else
namespace boost {
    namespace asio {
        typedef io_service io_context;
    }
}
#endif

#ifndef elif
#define elif else if
#endif

#ifndef F_OK
#define F_OK 0
#endif

#ifdef JEMALLOC
#ifdef _Win32
#include <jemalloc/jemalloc.h>
#else
#ifdef __cplusplus 
extern "C" {
#endif
    void*                                                                   je_malloc(size_t size);
    void                                                                    je_free(void* size);
#ifdef __cplusplus 
}
#endif
#endif
#endif

#include <list>
#include <vector>
#include <string>
#include <memory>
#include <functional>

#ifndef strcasecmp
#define strcasecmp strcasecmp_
#endif

#ifndef strncasecmp
#define strncasecmp strncasecmp_
#endif

#ifndef BOOST_ASIO_MOVE_CAST
#define BOOST_ASIO_MOVE_CAST(type) static_cast<type&&>
#endif

#ifndef BOOST_ASIO_MOVE_ARG
#define BOOST_ASIO_MOVE_ARG(type) type&&
#endif

typedef unsigned char                                                       Byte;
typedef signed char                                                         SByte;
typedef signed short int                                                    Int16;
typedef signed int                                                          Int32;
typedef signed long long                                                    Int64;
typedef unsigned short int                                                  UInt16;
typedef unsigned int                                                        UInt32;
typedef unsigned long long                                                  UInt64;
typedef double                                                              Double;
typedef float                                                               Single;
typedef bool                                                                Boolean;
typedef signed char                                                         Char;

inline int                                                                  strncasecmp_(const void* x, const void* y, size_t length) noexcept {
    if (x == y || length == 0) {
        return 0;
    }

    char* px = (char*)x;
    char* py = (char*)y;

    for (size_t i = 0; i < length; i++) {
        int xch = toupper(*px++);
        int ych = toupper(*py++);

        if (xch != ych) {
            return xch > ych ? 1 : -1;
        }
    }
    return 0;
}

inline int                                                                  strcasecmp_(const void* x, const void* y) noexcept {
    if (x == y) {
        return 0;
    }

    char* px = (char*)x;
    char* py = (char*)y;

    size_t xlen = strlen(px);
    size_t ylen = strlen(py);

    if (xlen != ylen) {
        return xlen > ylen ? 1 : -1;
    }
    return strncasecmp(x, y, xlen);
}

template<typename _Ty>
inline int                                                                  Tokenize(const _Ty& str, std::vector<_Ty>& tokens, const _Ty& delimiters) noexcept {
    if (str.empty()) {
        return 0;
    }
    elif(delimiters.empty()) {
        tokens.push_back(str);
        return 1;
    }

    char* deli_ptr = (char*)delimiters.data();
    char* deli_endptr = deli_ptr + delimiters.size();
    char* data_ptr = (char*)str.data();
    char* data_endptr = data_ptr + str.size();
    char* last_ptr = NULL;

    int length = 0;
    int seg = 0;
    while (data_ptr < data_endptr) {
        int ch = *data_ptr;
        int b = 0;
        for (char* p = deli_ptr; p < deli_endptr; p++) {
            if (*p == ch) {
                b = 1;
                break;
            }
        }
        if (b) {
            if (seg) {
                int sz = data_ptr - last_ptr;
                if (sz > 0) {
                    length++;
                    tokens.push_back(_Ty(last_ptr, sz));
                }
                seg = 0;
            }
        }
        elif(!seg) {
            seg = 1;
            last_ptr = data_ptr;
        }
        data_ptr++;
    }
    if ((seg && last_ptr) && last_ptr < data_ptr) {
        length++;
        tokens.push_back(_Ty(last_ptr, data_ptr - last_ptr));
    }
    return length;
}

template<typename _Ty>
inline _Ty                                                                  LTrim(const _Ty& s) noexcept {
    _Ty str = s;
    if (str.empty()) {
        return str;
    }

    int64_t pos = -1;
    for (size_t i = 0, l = str.size(); i < l; ++i) {
        char ch = str[i];
        if (ch == ' ' ||
            ch == '\0' ||
            ch == '\n' ||
            ch == '\r' ||
            ch == '\t') {
            pos = i + 1;
        }
        else {
            break;
        }
    }
    if (pos >= 0) {
        if (pos >= (int64_t)str.size()) {
            return "";
        }
        str = str.substr(pos);
    }
    return str;
}

template<typename _Ty>
inline _Ty                                                                  RTrim(const _Ty& s) noexcept {
    _Ty str = s;
    if (str.empty()) {
        return str;
    }

    int64_t pos = -1;
    int64_t i = str.size();
    i--;
    for (; i >= 0u; --i) {
        char ch = str[i];
        if (ch == ' ' ||
            ch == '\0' ||
            ch == '\n' ||
            ch == '\r' ||
            ch == '\t') {
            pos = i;
        }
        else {
            break;
        }
    }
    if (pos >= 0) {
        if (0 >= pos) {
            return "";
        }
        str = str.substr(0, pos);
    }
    return str;
}

template<typename _Ty>
inline _Ty                                                                  ToUpper(const _Ty& s) noexcept {
    _Ty r = s;
    if (!r.empty()) {
        std::transform(s.begin(), s.end(), r.begin(), toupper);
    }
    return r;
}

template<typename _Ty>
inline _Ty                                                                  ToLower(const _Ty& s) noexcept {
    _Ty r = s;
    if (!r.empty()) {
        std::transform(s.begin(), s.end(), r.begin(), tolower);
    }
    return r;
}

template<typename _Ty>
inline _Ty                                                                  Replace(const _Ty& s, const _Ty& old_value, const _Ty& new_value) noexcept {
    _Ty r = s;
    if (r.empty()) {
        return r;
    }
    do {
        typename _Ty::size_type pos = r.find(old_value);
        if (pos != _Ty::npos) {
            r.replace(pos, old_value.length(), new_value);
        }
        else {
            break;
        }
    } while (1);
    return r;
}

template<typename _Ty>
inline int                                                                  Split(const _Ty& str, std::vector<_Ty>& tokens, const _Ty& delimiters) noexcept {
    if (str.empty()) {
        return 0;
    }
    elif(delimiters.empty()) {
        tokens.push_back(str);
        return 1;
    }
    size_t last_pos = 0;
    size_t curr_cnt = 0;
    while (1) {
        size_t pos = str.find(delimiters, last_pos);
        if (pos == _Ty::npos) {
            pos = str.size();
        }

        size_t len = pos - last_pos;
        if (len != 0) {
            curr_cnt++;
            tokens.push_back(str.substr(last_pos, len));
        }

        if (pos == str.size()) {
            break;
        }
        last_pos = pos + delimiters.size();
    }
    return curr_cnt;
}

template<typename T>
inline constexpr T*                                                         addressof(const T& v) noexcept {
    return (T*)&reinterpret_cast<const char&>(v);
}

template<typename T>
inline constexpr T*                                                         addressof(const T* v) noexcept {
    return const_cast<T*>(v);
}

template<typename T>
inline constexpr T&                                                         constantof(const T& v) noexcept {
    return const_cast<T&>(v);
}

template<typename T>
inline constexpr T*                                                         constantof(const T* v) noexcept {
    return const_cast<T*>(v);
}

template<typename T>
inline constexpr T&&                                                        constant0f(const T&& v) noexcept {
    return const_cast<T&&>(v);
}

template<typename T>
inline constexpr T&&                                                        forward0f(const T& v) noexcept {
    return std::forward<T>(constantof(v));
}

inline void*                                                                Malloc(size_t size_) noexcept {
    if (!size_) {
        return NULL;
    }

#ifdef JEMALLOC
    return (void*)::je_malloc(size_);
#else
    return (void*)::malloc(size_);
#endif
}

inline void                                                                 Mfree(const void* p) noexcept {
    if (p) {
#ifdef JEMALLOC
        ::je_free((void*)p);
#else
        ::free((void*)p);
#endif
    }
}

void                                                                        SetThreadPriorityToMaxLevel() noexcept;

void                                                                        SetProcessPriorityToMaxLevel() noexcept;

bool                                                                        FileWriteAllBytes(const char* path, const void* data, int length) noexcept;

template<typename T>
inline std::shared_ptr<T>                                                   make_shared_alloc(int length) noexcept {
    static_assert(sizeof(T) > 0, "can't make pointer to incomplete type");

    // https://pkg.go.dev/github.com/google/agi/core/os/device
    // ARM64v8a: __ALIGN(8)
    // ARMv7a  : __ALIGN(4)
    // X86_64  : __ALIGN(8)
    // X64     : __ALIGN(4)
    if (length < 1) {
        return NULL;
    }

    T* p = (T*)::Malloc(length * sizeof(T));
    return std::shared_ptr<T>(p, ::Mfree);
}

template<typename T, typename... A>
inline std::shared_ptr<T>                                                   make_shared_object(A&&... args) noexcept {
    static_assert(sizeof(T) > 0, "can't make pointer to incomplete type");

    T* p = (T*)::Malloc(sizeof(T));
    return std::shared_ptr<T>(new (p) T(std::forward<A&&>(args)...),
        [](T* p) noexcept {
            p->~T();
            ::Mfree(p);
        });
}

namespace network {
    namespace asio {
        template<typename AsyncWriteStream, typename MutableBufferSequence>
        inline bool                                                         async_read(AsyncWriteStream& stream, const MutableBufferSequence& buffers, const boost::asio::yield_context& y) noexcept {
            if (!buffers.data() || !buffers.size()) {
                return false;
            }

            boost::system::error_code ec;
            try {
                std::size_t bytes_transferred = boost::asio::async_read(stream, constantof(buffers), y[ec]);
                if (ec) {
                    return false;
                }
                return bytes_transferred == buffers.size();
            }
            catch (std::exception&) {
                return false;
            }
        }

        template<typename AsyncWriteStream, typename ConstBufferSequence>
        inline bool                                                         async_write(AsyncWriteStream& stream, const ConstBufferSequence& buffers, const boost::asio::yield_context& y) noexcept {
            if (!buffers.data() || !buffers.size()) {
                return false;
            }

            boost::system::error_code ec;
            try {
                std::size_t bytes_transferred = boost::asio::async_write(stream, constantof(buffers), y[ec]);
                if (ec) {
                    return false;
                }
                return bytes_transferred == buffers.size();
            }
            catch (std::exception&) {
                return false;
            }
        }

        inline int                                                          async_connect(boost::asio::ip::tcp::socket& socket, const boost::asio::ip::tcp::endpoint& remoteEP, const boost::asio::yield_context& y) noexcept {
            boost::asio::ip::address address = remoteEP.address();
            if (address.is_unspecified() || address.is_multicast()) {
                return false;
            }

            int port = remoteEP.port();
            if (port < 1 || port > 65535) {
                return false;
            }

            boost::system::error_code ec;
            try {
                socket.async_connect(remoteEP, y[ec]);
                return ec.value();
            }
            catch (std::exception&) {
                return -1;
            }
        }
    }
}
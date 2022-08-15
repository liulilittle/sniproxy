#include "sniproxy.h"
#include "json/json.h"

#ifndef SNIPROXY_VERSION
#define SNIPROXY_VERSION ("1.0.0")
#endif

inline static std::string
EXEF() noexcept {
#ifdef _WIN32
    char exe[8096];
    GetModuleFileNameA(NULL, exe, sizeof(exe));
    return exe;
#else
    char sz[260 + 1];
    int dw = readlink("/proc/self/exe", sz, 260);
    sz[dw] = '\x0';
    return dw <= 0 ? "" : std::string(sz, dw);
#endif
}

inline static std::string
CWDP() noexcept {
#ifdef _WIN32
    char cwd[8096];
    GetCurrentDirectoryA(sizeof(cwd), cwd);
    return cwd;
#else
    char sz[260 + 1];
    return getcwd(sz, 260);
#endif
}

inline static std::string
EXEN() noexcept {
    std::string exe = EXEF();
    if (exe.empty()) {
        return "";
    }
#ifdef _WIN32
    size_t sz = exe.find_last_of('\\');
#else
    size_t sz = exe.find_last_of('/');
#endif
    if (sz == std::string::npos) {
        return exe;
    }
    return exe.substr(sz + 1);
}

inline static bool
exfile(const std::string& path) noexcept {
    if (path.empty()) {
        return false;
    }
    return ::access(path.data(), F_OK) == 0;
}

inline static std::string
rbfile(const std::string& path) noexcept {
    bool fexists_ = exfile(path);
    if (!fexists_) {
        return "";
    }

    FILE* file_ = ::fopen(path.data(), "rb");
    if (!file_) {
        return "";
    }

    MemoryStream stream_;
    char buff_[1400];
    for (;;) {
        size_t count_ = ::fread(buff_, 1, sizeof(buff_), file_);
        if (count_ == 0) {
            break;
        }
        stream_.Write(buff_, 0, count_);
    }

    fclose(file_);
    if (stream_.GetPosition() > 0) {
        return std::string((char*)stream_.GetBuffer().get(), stream_.GetPosition());
    }
    return "";
}

inline static std::string
rbfile(int argc, const char* argv[]) noexcept {
    std::string path;
    if (argc > 1) {
        path = argv[1];
    }

    if (!exfile(path)) {
        path = "appsettings.json";
    }
    return std::move(rbfile(path));
}

template<typename ...A>
inline static void 
printof(const char* _Format, A&&... _Args) noexcept {
    fprintf(stdout, _Format, std::forward<A&&>(_Args)...);
}

inline static std::shared_ptr<server_configuration>
load_config(int argc, const char* argv[]) noexcept {
    std::string json_str = rbfile(argc, argv);
    std::shared_ptr<server_configuration> configuration_ = make_shared_object<server_configuration>();
    if (json_str.empty()) {
        return NULL;
    }

    Json::Value json;
    Json::Reader reader;

    std::size_t offset_ = json_str.find('{');
    if (offset_ == std::string::npos) {
        return NULL;
    }

    if (json_str.find('}', offset_) == std::string::npos) {
        return NULL;
    }

    reader.parse(json_str.data() + offset_, json_str.data() + json_str.size(), json);
    if (!json.isObject()) {
        return NULL;
    }

    // 从字符串解析的JSON格式对象中填充数据到配置文件
    configuration_->concurrent = json["concurrent"].asInt();
    configuration_->backlog = json["backlog"].asInt();
    configuration_->fast_open = json["fast-open"].asBool();
    configuration_->turbo.lan = json["turbo"]["lan"].asBool();
    configuration_->turbo.wan = json["turbo"]["wan"].asBool();
    configuration_->listen.http = json["listen"]["http"].asInt();
    configuration_->listen.http_ssl = json["listen"]["http-ssl"].asInt();
    configuration_->reverse_proxy.host = json["reverse-proxy"]["host"].asString();
    configuration_->reverse_proxy.http = json["reverse-proxy"]["http"].asString();
    configuration_->reverse_proxy.http_ssl = json["reverse-proxy"]["http-ssl"].asString();
    configuration_->connect.timeout = json["connect"]["timeout"].asInt();

    // 检查用户配置文件参数设置的合法性
    if (configuration_->listen.http <= IPEndPoint::MinPort || configuration_->listen.http > IPEndPoint::MaxPort) {
        return NULL;
    }
    elif(configuration_->listen.http_ssl <= IPEndPoint::MinPort || configuration_->listen.http_ssl > IPEndPoint::MaxPort) {
        return NULL;
    }
    elif(configuration_->backlog < 1 || configuration_->connect.timeout < 1) {
        return NULL;
    }

    // 检查反向代理配置选项的合法性
    std::string& reverse_host = configuration_->reverse_proxy.host;
    if (reverse_host.size()) {
        std::size_t index = reverse_host.find('.');
        if (index == std::string::npos) {
            reverse_host.clear();
        }
        elif(RTrim(LTrim(reverse_host.substr(0, index))).empty()) {
            reverse_host.clear();
        }
        elif(RTrim(LTrim(reverse_host.substr(index + 1))).empty()) {
            reverse_host.clear();
        }
        else {
            const int MAX_REVERSE_SERVER = 2;
            std::string* reverse_servers[MAX_REVERSE_SERVER] = {
                std::addressof(configuration_->reverse_proxy.http),
                std::addressof(configuration_->reverse_proxy.http_ssl)
            };
            std::size_t reverse_server_ports[MAX_REVERSE_SERVER] = { 80, 443 };

            for (int i = 0; i < MAX_REVERSE_SERVER; i++) {
                std::string& reverse_server = *reverse_servers[i];
                if (reverse_server.empty()) {
                    continue;
                }

                IPEndPoint ipep = Ipep::GetEndPoint(reverse_server, false);
                if (IPEndPoint::IsInvalid(ipep)) {
                    reverse_server.clear();
                    continue;
                }

                if (ipep.Port <= IPEndPoint::MinPort || ipep.Port > IPEndPoint::MaxPort) {
                    int reverse_server_port_ = reverse_server_ports[i];
                    if (reverse_server_port_ == configuration_->listen.http ||
                        reverse_server_port_ == configuration_->listen.http_ssl) {
                        if (ipep.IsLoopback()) {
                            reverse_server.clear();
                            continue;
                        }
                    }

                    int address_size_;
                    Byte* address_bytes_ = ipep.GetAddressBytes(address_size_);
                    reverse_server = IPEndPoint(ipep.GetAddressFamily(), address_bytes_,
                        address_size_, reverse_server_port_).ToString();
                    continue;
                }
            }

            if (reverse_servers[0]->empty() && reverse_servers[1]->empty()) {
                reverse_host.clear();
            }
        }
    }
    if (reverse_host.empty()) {
        reverse_host.clear();
        configuration_->reverse_proxy.http.clear();
        configuration_->reverse_proxy.http_ssl.clear();
    }

    // 返回整理及效验以后的服务器配置文件
    if (configuration_->concurrent < 1) {
        configuration_->concurrent = Hosting::GetMaxConcurrency();
    }
    return configuration_;
}

int main(int argc, const char* argv[]) noexcept {
#ifdef _WIN32
    SetConsoleTitle(TEXT("SNI PROXY"));
#endif
    std::shared_ptr<server_configuration> configuration_ = load_config(argc, argv);
    if (configuration_) {
#ifndef _WIN32
        // ignore SIGPIPE
        signal(SIGPIPE, SIG_IGN);
        signal(SIGABRT, SIG_IGN);
#endif
        SetProcessPriorityToMaxLevel();
        SetThreadPriorityToMaxLevel();
    }
    else {
        std::string messages_ = "Copyright (C) 2017 ~ 2022 SupersocksR ORG. All rights reserved.\r\n";
        messages_ += "SNI PROXY(X) %s Version\r\n\r\n";
        messages_ += "Cwd:\r\n    " + CWDP() + "\r\n";
        messages_ += "Usage:\r\n";
        messages_ += "    .%s%s appsettings.json \r\n";
        messages_ += "Contact us:\r\n";
        messages_ += "    https://t.me/supersocksr_group \r\n";
#ifdef _WIN32
        fprintf(stdout, messages_.data(), SNIPROXY_VERSION, "\\", EXEN().data());
        system("pause");
#else
        fprintf(stdout, messages_.data(), SNIPROXY_VERSION, "/", EXEN().data());
#endif
        return 0;
    }

    std::shared_ptr<Hosting>& hosting_ = server_hosting();
    if (!hosting_) {
        hosting_ = make_shared_object<Hosting>(configuration_->concurrent);
        hosting_->Run();
    }

    std::shared_ptr<server> server_ = make_shared_object<server>(hosting_, configuration_);
    server_->Run(
        [hosting_, server_, configuration_]() noexcept {
            using ACCEPT_SOCKET_ORIGIN = server::ACCEPT_SOCKET_ORIGIN;
            auto print0f = [&server_](const char* _Format, ACCEPT_SOCKET_ORIGIN _Origin) noexcept {
                boost::asio::ip::tcp::endpoint localEP = server_->GetLocalEndPoint(_Origin);
                int localPort = localEP.port(); // boost::asio::ip::port_type
                if (localPort > IPEndPoint::MinPort && localPort <= IPEndPoint::MaxPort) {
                    printof(_Format, IPEndPoint::ToEndPoint(localEP).ToString().data());
                }
            };
            printof("%s\r\nLoopback:\r\n", "Application started. Press Ctrl+C to shut down.");
            printof("Max Concurrent        : %d\r\n", hosting_->GetConcurrency());
            printof("Cwd                   : %s\r\n", CWDP().data());
            print0f("HTTP                  : %s\r\n", ACCEPT_SOCKET_ORIGIN::ACCEPT_SOCKET_ORIGIN_HTTP);
            print0f("HTTP SSL              : %s\r\n", ACCEPT_SOCKET_ORIGIN::ACCEPT_SOCKET_ORIGIN_HTTP_SSL);
        });
    return 0;
}
#pragma once

#include <functional>
#include <map>
#include <string>
#include <thread>

#include "mdns_cpp/utils.hpp"

#ifdef _WIN32
#include <iphlpapi.h>
#include <winsock2.h>
#else
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#endif

namespace mdns_cpp {

enum class RecordType {
  IGNORE = 0,
  // Address
  A = 1,
  // Domain Name pointer
  PTR = 12,
  // Arbitrary text string
  TXT = 16,
  // IP6 Address [Thomson]
  AAAA = 28,
  // Server Selection [RFC2782]
  SRV = 33,
  // Any available records
  ANY = 255
};

struct SRVRecord {
  uint16_t priority;
  uint16_t weight;
  uint16_t port;
  std::string name;

  auto operator<=>(const SRVRecord &) const = default;
};

struct Record {
  std::string origin;
  RecordType type;
  std::variant<std::string, std::map<std::string, std::string>, SRVRecord> content;
  uint16_t rclass;
  uint32_t ttl;

  bool operator==(const Record &other) const {
    return std::tie(origin, type, content, rclass, ttl) ==
           std::tie(other.origin, other.type, other.content, other.rclass, other.ttl);
  }
};

class mDNS {
 public:
  ~mDNS();

  void startService(bool dumpMode = false);
  void stopService();
  bool isServiceRunning();

  void setServiceHostname(const std::string &hostname);
  void setServicePort(std::uint16_t port);
  void setServiceName(const std::string &name);

  void setServiceTxtRecord(const std::vector<std::pair<std::string, std::string>> kvPairs);

  using ServiceQueries = std::vector<std::pair<std::string, RecordType>>;
  std::vector<Record> executeQuery(ServiceQueries service);
  // this is still blocking
  void executeQuery(ServiceQueries service, std::function<void(Record)> onNewRecord, int timeoutInSecs = 10);
  void executeDiscovery();

 private:
  void runMainLoop();
  void runDumpMode(int *sockets, int num_sockets);
  int openClientSockets(int *sockets, int max_sockets, int port);
  int openServiceSockets(int *sockets, int max_sockets);

  std::string hostname_{"dummy-host"};
  std::string name_{"_http._tcp.local."};
  std::uint16_t port_{42424};
  std::vector<std::pair<std::string, std::string>> txt_records_;

  std::atomic<bool> running_{false};
  bool dumpMode_{false};

  struct sockaddr_in service_address_ipv4_;
  struct sockaddr_in6 service_address_ipv6_;

  std::thread worker_thread_;
};

}  // namespace mdns_cpp

// Standalone original QUICHE PRR runner; see README.md for pinned inputs.
#include <cstdint>
#include <iostream>

#define QUICHE_EXPORT
namespace quic {
using QuicByteCount = uint64_t;
constexpr uint64_t kMaxSegmentSize = 1460;
}

#include "quiche/quic/core/congestion_control/prr_sender.h"
#include "prr.cc"

int main() {
  bool first = true;
  quic::PrrSender sender;
  sender.OnPacketLost(46720);
  std::cout << "[\n";
  for (int i = 0; i < 40; ++i) {
    char event = i % 3 == 0 ? 's' : 'a';
    uint64_t bytes = uint64_t(i % 5 + 1) * 1460;
    if (event == 's') sender.OnPacketSent(bytes);
    else sender.OnPacketAcked(bytes);
    if (!first) std::cout << ",\n";
    first = false;
    std::cout << "{\"event\":\"" << event << "\",\"bytes\":" << bytes
              << ",\"allowed\":[";
    bool comma = false;
    for (uint64_t in_flight : {0, 1000, 10000, 39712, 50000}) {
      if (comma) std::cout << ",";
      comma = true;
      std::cout << (sender.CanSend(39712, in_flight, 39712) ? "true" : "false");
    }
    std::cout << "]}";
  }
  std::cout << "\n]\n";
}

// Standalone QUICHE reference runner; see README.md for source pins.
#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <iostream>

#define QUICHE_EXPORT
#define QUICHE_DCHECK(x) assert(x)
#define QUICHE_DCHECK_LT(x, y) assert((x) < (y))

struct NullLog {
  template <class T> NullLog &operator<<(T const &) { return *this; }
};
#define QUIC_DVLOG(x) NullLog()

namespace quic {
using QuicByteCount = uint64_t;
using QuicPacketCount = uint64_t;
constexpr uint32_t kDefaultNumConnections = 2;
constexpr uint64_t kDefaultTCPMSS = 1460;
constexpr uint64_t kNumMicrosPerSecond = 1000000;
struct QuicClock {};
struct QuicTime {
  int64_t micros = 0;
  struct Delta {
    int64_t micros;
    static Delta FromMilliseconds(int64_t ms) { return {ms * 1000}; }
    int64_t ToMicroseconds() const { return micros; }
  };
  static QuicTime Zero() { return {}; }
  bool IsInitialized() const { return micros != 0; }
  friend QuicTime operator+(QuicTime a, Delta b) {
    return {a.micros + b.micros};
  }
  friend Delta operator-(QuicTime a, QuicTime b) {
    return {a.micros - b.micros};
  }
};
} // namespace quic

#include "chrome-cubic.h"
#include "chrome-cubic.cc"

int main() {
  bool first = true;
  std::cout << "[\n";
  for (int connections : {1, 2, 4}) {
    for (int scenario : {0, 1, 2}) {
      quic::CubicBytes c(nullptr);
      c.SetNumConnections(connections);
      uint64_t cwnd = c.CongestionWindowAfterPacketLoss(100 * 1460);
      for (int i = 0; i < 60; i++) {
        auto time_ms = uint64_t(i * (scenario == 0 ? 50 : 1000));
        if (scenario == 2 && i == 20) c.OnApplicationLimited();
        if (scenario == 2 && i == 40) {
          cwnd = c.CongestionWindowAfterPacketLoss(cwnd);
        }
        auto acked = uint64_t(i % 3 == 0 ? 23 * 1460 : 1460 / 3);
        cwnd = c.CongestionWindowAfterAck(
            acked, cwnd, quic::QuicTime::Delta::FromMilliseconds(100),
            quic::QuicTime{int64_t(1000 + time_ms * 1000)});
        if (!first) std::cout << ",\n";
        first = false;
        std::cout << " [" << connections << "," << scenario << "," << i << ","
                  << time_ms << "," << acked << "," << cwnd << "]";
      }
    }
  }
  std::cout << "\n]\n";
}

// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef MOSH_CRYPTO_V3_H
#define MOSH_CRYPTO_V3_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace MoshV3 {

static const std::size_t BOOTSTRAP_LEN = 32;
static const std::size_t SECRET_LEN = 32;
static const std::size_t KEY_LEN = 32;
static const std::size_t IV_LEN = 12;
static const std::size_t TAG_LEN = 16;
static const std::size_t HEADER_LEN = 18;

class CryptoError : public std::runtime_error {
public:
  explicit CryptoError(const std::string &what) : std::runtime_error(what) {}
};

enum class Direction { ClientToServer, ServerToClient };

struct Header {
  uint8_t version;
  uint8_t flags;
  uint32_t send_epoch;
  uint32_t ack_epoch;
  uint64_t packet_seq;

  Header();
  std::array<unsigned char, HEADER_LEN> encode() const;
  static Header decode(const unsigned char *data, std::size_t len);
};

class TrafficKey {
public:
  TrafficKey();
  TrafficKey(const std::array<unsigned char, KEY_LEN> &key,
             const std::array<unsigned char, IV_LEN> &iv);
  ~TrafficKey();
  TrafficKey(TrafficKey &&other) noexcept;
  TrafficKey &operator=(TrafficKey &&other) noexcept;
  TrafficKey(const TrafficKey &) = delete;
  TrafficKey &operator=(const TrafficKey &) = delete;

  std::array<unsigned char, IV_LEN> nonce(uint64_t packet_seq) const;
  std::vector<unsigned char> encrypt(const Header &header,
                                     const unsigned char *plaintext,
                                     std::size_t plaintext_len) const;
  std::vector<unsigned char> decrypt(const Header &header,
                                     const unsigned char *ciphertext_and_tag,
                                     std::size_t ciphertext_and_tag_len) const;

  bool valid() const { return valid_; }

private:
  std::array<unsigned char, KEY_LEN> key_;
  std::array<unsigned char, IV_LEN> iv_;
  bool valid_;
  void clear();
};

class TrafficSecret {
public:
  TrafficSecret();
  explicit TrafficSecret(const std::array<unsigned char, SECRET_LEN> &secret);
  ~TrafficSecret();
  TrafficSecret(TrafficSecret &&other) noexcept;
  TrafficSecret &operator=(TrafficSecret &&other) noexcept;
  TrafficSecret(const TrafficSecret &) = delete;
  TrafficSecret &operator=(const TrafficSecret &) = delete;

  TrafficKey derive_key() const;
  TrafficSecret next() const;
  void advance();
  bool valid() const { return valid_; }

private:
  std::array<unsigned char, SECRET_LEN> secret_;
  bool valid_;
  void clear();
};

struct InitialSecrets {
  TrafficSecret client_to_server;
  TrafficSecret server_to_client;
};

enum class EndpointRole { Client, Server };

struct OpenResult {
  Header header;
  std::vector<unsigned char> plaintext;
};

class EpochSession {
public:
  EpochSession(EndpointRole role, InitialSecrets initial);
  ~EpochSession() = default;
  EpochSession(EpochSession &&other) noexcept = default;
  EpochSession &operator=(EpochSession &&other) noexcept = default;
  EpochSession(const EpochSession &) = delete;
  EpochSession &operator=(const EpochSession &) = delete;

  std::vector<unsigned char> seal(uint64_t packet_seq,
                                  const unsigned char *plaintext,
                                  std::size_t plaintext_len);
  OpenResult open(const unsigned char *datagram, std::size_t datagram_len);

  bool can_rekey_send() const;
  void rekey_send();
  void discard_previous_receive_key();

  uint32_t send_epoch() const { return send_epoch_; }
  uint32_t receive_epoch() const { return receive_epoch_; }
  uint32_t peer_acknowledged_send_epoch() const { return peer_ack_epoch_; }
  uint64_t packets_in_send_epoch() const { return packets_in_send_epoch_; }

private:
  TrafficSecret send_secret_;
  TrafficKey send_key_;
  uint32_t send_epoch_;
  uint32_t peer_ack_epoch_;
  uint64_t packets_in_send_epoch_;

  TrafficSecret receive_secret_;
  TrafficKey receive_key_;
  TrafficKey previous_receive_key_;
  uint32_t receive_epoch_;
  bool previous_receive_key_valid_;

  void note_authenticated_ack(uint32_t ack_epoch);
};

std::array<unsigned char, BOOTSTRAP_LEN> generate_bootstrap();
std::string encode_bootstrap_base64(const std::array<unsigned char, BOOTSTRAP_LEN> &bootstrap);
std::array<unsigned char, BOOTSTRAP_LEN> decode_bootstrap_base64(const std::string &encoded);
InitialSecrets derive_initial_secrets(const std::array<unsigned char, BOOTSTRAP_LEN> &bootstrap);
void secure_zero(void *ptr, std::size_t len);

} // namespace MoshV3

#endif

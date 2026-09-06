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

std::array<unsigned char, BOOTSTRAP_LEN> generate_bootstrap();
std::string encode_bootstrap_base64(const std::array<unsigned char, BOOTSTRAP_LEN> &bootstrap);
std::array<unsigned char, BOOTSTRAP_LEN> decode_bootstrap_base64(const std::string &encoded);
InitialSecrets derive_initial_secrets(const std::array<unsigned char, BOOTSTRAP_LEN> &bootstrap);
void secure_zero(void *ptr, std::size_t len);

} // namespace MoshV3

#endif

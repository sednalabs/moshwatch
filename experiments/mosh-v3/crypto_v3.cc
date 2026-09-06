// SPDX-License-Identifier: AGPL-3.0-or-later

#include "crypto_v3.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <memory>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

namespace MoshV3 {
namespace {

typedef std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> PkeyCtx;
typedef std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> CipherCtx;

void write_u32_be(unsigned char *out, uint32_t value) {
  out[0] = static_cast<unsigned char>(value >> 24);
  out[1] = static_cast<unsigned char>(value >> 16);
  out[2] = static_cast<unsigned char>(value >> 8);
  out[3] = static_cast<unsigned char>(value);
}

void write_u64_be(unsigned char *out, uint64_t value) {
  for (int i = 7; i >= 0; --i) {
    out[i] = static_cast<unsigned char>(value);
    value >>= 8;
  }
}

uint32_t read_u32_be(const unsigned char *in) {
  return (static_cast<uint32_t>(in[0]) << 24)
       | (static_cast<uint32_t>(in[1]) << 16)
       | (static_cast<uint32_t>(in[2]) << 8)
       | static_cast<uint32_t>(in[3]);
}

uint64_t read_u64_be(const unsigned char *in) {
  uint64_t value = 0;
  for (int i = 0; i < 8; ++i) value = (value << 8) | in[i];
  return value;
}

std::array<unsigned char, SECRET_LEN> hkdf_extract(
    const unsigned char *ikm, std::size_t ikm_len,
    const unsigned char *salt, std::size_t salt_len) {
  PkeyCtx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL), EVP_PKEY_CTX_free);
  if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0
      || EVP_PKEY_CTX_hkdf_mode(ctx.get(), EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0
      || EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0
      || EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt, salt_len) <= 0
      || EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), ikm, ikm_len) <= 0) {
    throw CryptoError("HKDF extract initialization failed");
  }
  std::array<unsigned char, SECRET_LEN> out;
  std::size_t out_len = out.size();
  if (EVP_PKEY_derive(ctx.get(), out.data(), &out_len) <= 0 || out_len != out.size()) {
    secure_zero(out.data(), out.size());
    throw CryptoError("HKDF extract failed");
  }
  return out;
}

template <std::size_t N>
std::array<unsigned char, N> hkdf_expand(
    const unsigned char *prk, std::size_t prk_len, const char *label) {
  PkeyCtx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL), EVP_PKEY_CTX_free);
  const std::size_t label_len = std::strlen(label);
  if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0
      || EVP_PKEY_CTX_hkdf_mode(ctx.get(), EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0
      || EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0
      || EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), prk, prk_len) <= 0
      || EVP_PKEY_CTX_add1_hkdf_info(ctx.get(),
           reinterpret_cast<const unsigned char *>(label), label_len) <= 0) {
    throw CryptoError("HKDF expand initialization failed");
  }
  std::array<unsigned char, N> out;
  std::size_t out_len = out.size();
  if (EVP_PKEY_derive(ctx.get(), out.data(), &out_len) <= 0 || out_len != out.size()) {
    secure_zero(out.data(), out.size());
    throw CryptoError("HKDF expand failed");
  }
  return out;
}

void ensure_int_len(std::size_t len) {
  if (len > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    throw CryptoError("AEAD input too large");
  }
}

} // namespace

void secure_zero(void *ptr, std::size_t len) {
  if (ptr && len) OPENSSL_cleanse(ptr, len);
}

Header::Header() : version(3), flags(0), send_epoch(0), ack_epoch(0), packet_seq(0) {}

std::array<unsigned char, HEADER_LEN> Header::encode() const {
  if (version != 3 || flags != 0) throw CryptoError("invalid v3 header fields");
  std::array<unsigned char, HEADER_LEN> out;
  out[0] = version;
  out[1] = flags;
  write_u32_be(out.data() + 2, send_epoch);
  write_u32_be(out.data() + 6, ack_epoch);
  write_u64_be(out.data() + 10, packet_seq);
  return out;
}

Header Header::decode(const unsigned char *data, std::size_t len) {
  if (!data || len < HEADER_LEN) throw CryptoError("short v3 header");
  Header h;
  h.version = data[0];
  h.flags = data[1];
  if (h.version != 3 || h.flags != 0) throw CryptoError("unsupported v3 header");
  h.send_epoch = read_u32_be(data + 2);
  h.ack_epoch = read_u32_be(data + 6);
  h.packet_seq = read_u64_be(data + 10);
  return h;
}

TrafficKey::TrafficKey() : key_(), iv_(), valid_(false) {}
TrafficKey::TrafficKey(const std::array<unsigned char, KEY_LEN> &key,
                       const std::array<unsigned char, IV_LEN> &iv)
  : key_(key), iv_(iv), valid_(true) {}
TrafficKey::~TrafficKey() { clear(); }

TrafficKey::TrafficKey(TrafficKey &&other) noexcept
  : key_(other.key_), iv_(other.iv_), valid_(other.valid_) { other.clear(); }

TrafficKey &TrafficKey::operator=(TrafficKey &&other) noexcept {
  if (this != &other) {
    clear();
    key_ = other.key_;
    iv_ = other.iv_;
    valid_ = other.valid_;
    other.clear();
  }
  return *this;
}

void TrafficKey::clear() {
  secure_zero(key_.data(), key_.size());
  secure_zero(iv_.data(), iv_.size());
  valid_ = false;
}

std::array<unsigned char, IV_LEN> TrafficKey::nonce(uint64_t packet_seq) const {
  if (!valid_) throw CryptoError("invalid traffic key");
  std::array<unsigned char, IV_LEN> out = iv_;
  unsigned char seq[8];
  write_u64_be(seq, packet_seq);
  for (std::size_t i = 0; i < 8; ++i) out[4 + i] ^= seq[i];
  secure_zero(seq, sizeof(seq));
  return out;
}

std::vector<unsigned char> TrafficKey::encrypt(
    const Header &header, const unsigned char *plaintext, std::size_t plaintext_len) const {
  if (!valid_) throw CryptoError("invalid traffic key");
  if (!plaintext && plaintext_len) throw CryptoError("null plaintext");
  ensure_int_len(plaintext_len);
  const std::array<unsigned char, HEADER_LEN> aad = header.encode();
  const std::array<unsigned char, IV_LEN> n = nonce(header.packet_seq);
  CipherCtx ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), NULL, NULL, NULL) <= 0
      || EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, IV_LEN, NULL) <= 0
      || EVP_EncryptInit_ex(ctx.get(), NULL, NULL, key_.data(), n.data()) <= 0) {
    throw CryptoError("ChaCha20-Poly1305 encryption initialization failed");
  }
  int out_len = 0;
  if (EVP_EncryptUpdate(ctx.get(), NULL, &out_len, aad.data(), aad.size()) <= 0) {
    throw CryptoError("AEAD AAD encryption failed");
  }
  std::vector<unsigned char> out(plaintext_len + TAG_LEN);
  int written = 0;
  if (plaintext_len && EVP_EncryptUpdate(ctx.get(), out.data(), &written, plaintext,
                                         static_cast<int>(plaintext_len)) <= 0) {
    throw CryptoError("AEAD encryption failed");
  }
  int final_written = 0;
  if (EVP_EncryptFinal_ex(ctx.get(), out.data() + written, &final_written) <= 0
      || static_cast<std::size_t>(written + final_written) != plaintext_len
      || EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, TAG_LEN,
                             out.data() + plaintext_len) <= 0) {
    secure_zero(out.data(), out.size());
    throw CryptoError("AEAD encryption finalization failed");
  }
  return out;
}

std::vector<unsigned char> TrafficKey::decrypt(
    const Header &header, const unsigned char *ciphertext_and_tag,
    std::size_t ciphertext_and_tag_len) const {
  if (!valid_) throw CryptoError("invalid traffic key");
  if (!ciphertext_and_tag || ciphertext_and_tag_len < TAG_LEN) {
    throw CryptoError("short v3 ciphertext");
  }
  const std::size_t ciphertext_len = ciphertext_and_tag_len - TAG_LEN;
  ensure_int_len(ciphertext_len);
  const std::array<unsigned char, HEADER_LEN> aad = header.encode();
  const std::array<unsigned char, IV_LEN> n = nonce(header.packet_seq);
  CipherCtx ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), NULL, NULL, NULL) <= 0
      || EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, IV_LEN, NULL) <= 0
      || EVP_DecryptInit_ex(ctx.get(), NULL, NULL, key_.data(), n.data()) <= 0) {
    throw CryptoError("ChaCha20-Poly1305 decryption initialization failed");
  }
  int out_len = 0;
  if (EVP_DecryptUpdate(ctx.get(), NULL, &out_len, aad.data(), aad.size()) <= 0) {
    throw CryptoError("AEAD AAD decryption failed");
  }
  std::vector<unsigned char> out(ciphertext_len);
  int written = 0;
  if (ciphertext_len && EVP_DecryptUpdate(ctx.get(), out.data(), &written,
                                          ciphertext_and_tag,
                                          static_cast<int>(ciphertext_len)) <= 0) {
    secure_zero(out.data(), out.size());
    throw CryptoError("AEAD decryption failed");
  }
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, TAG_LEN,
                          const_cast<unsigned char *>(ciphertext_and_tag + ciphertext_len)) <= 0) {
    secure_zero(out.data(), out.size());
    throw CryptoError("AEAD tag setup failed");
  }
  int final_written = 0;
  if (EVP_DecryptFinal_ex(ctx.get(), out.data() + written, &final_written) <= 0
      || static_cast<std::size_t>(written + final_written) != ciphertext_len) {
    secure_zero(out.data(), out.size());
    throw CryptoError("v3 packet failed integrity check");
  }
  return out;
}

TrafficSecret::TrafficSecret() : secret_(), valid_(false) {}
TrafficSecret::TrafficSecret(const std::array<unsigned char, SECRET_LEN> &secret)
  : secret_(secret), valid_(true) {}
TrafficSecret::~TrafficSecret() { clear(); }

TrafficSecret::TrafficSecret(TrafficSecret &&other) noexcept
  : secret_(other.secret_), valid_(other.valid_) { other.clear(); }

TrafficSecret &TrafficSecret::operator=(TrafficSecret &&other) noexcept {
  if (this != &other) {
    clear();
    secret_ = other.secret_;
    valid_ = other.valid_;
    other.clear();
  }
  return *this;
}

void TrafficSecret::clear() {
  secure_zero(secret_.data(), secret_.size());
  valid_ = false;
}

TrafficKey TrafficSecret::derive_key() const {
  if (!valid_) throw CryptoError("invalid traffic secret");
  std::array<unsigned char, KEY_LEN> key =
      hkdf_expand<KEY_LEN>(secret_.data(), secret_.size(), "mosh-v3 key");
  std::array<unsigned char, IV_LEN> iv =
      hkdf_expand<IV_LEN>(secret_.data(), secret_.size(), "mosh-v3 iv");
  TrafficKey result(key, iv);
  secure_zero(key.data(), key.size());
  secure_zero(iv.data(), iv.size());
  return result;
}

TrafficSecret TrafficSecret::next() const {
  if (!valid_) throw CryptoError("invalid traffic secret");
  std::array<unsigned char, SECRET_LEN> next_secret =
      hkdf_expand<SECRET_LEN>(secret_.data(), secret_.size(), "mosh-v3 traffic update");
  TrafficSecret result(next_secret);
  secure_zero(next_secret.data(), next_secret.size());
  return result;
}

void TrafficSecret::advance() {
  TrafficSecret next_secret = next();
  *this = std::move(next_secret);
}

EpochSession::EpochSession(EndpointRole role, InitialSecrets initial)
  : send_secret_(), send_key_(), send_epoch_(0), peer_ack_epoch_(0),
    packets_in_send_epoch_(0), receive_secret_(), receive_key_(),
    previous_receive_key_(), receive_epoch_(0), previous_receive_key_valid_(false) {
  if (role == EndpointRole::Client) {
    send_secret_ = std::move(initial.client_to_server);
    receive_secret_ = std::move(initial.server_to_client);
  } else {
    send_secret_ = std::move(initial.server_to_client);
    receive_secret_ = std::move(initial.client_to_server);
  }
  send_key_ = send_secret_.derive_key();
  receive_key_ = receive_secret_.derive_key();
}

bool EpochSession::can_rekey_send() const {
  return peer_ack_epoch_ >= send_epoch_;
}

void EpochSession::rekey_send() {
  if (!can_rekey_send()) {
    throw CryptoError("cannot advance an unacknowledged send epoch");
  }
  if (send_epoch_ == std::numeric_limits<uint32_t>::max()) {
    throw CryptoError("send epoch exhausted");
  }
  send_secret_.advance();
  send_key_ = send_secret_.derive_key();
  ++send_epoch_;
  packets_in_send_epoch_ = 0;
}

std::vector<unsigned char> EpochSession::seal(
    uint64_t packet_seq, const unsigned char *plaintext,
    std::size_t plaintext_len) {
  if (packets_in_send_epoch_ == std::numeric_limits<uint64_t>::max()) {
    throw CryptoError("send packet counter exhausted");
  }
  Header header;
  header.send_epoch = send_epoch_;
  header.ack_epoch = receive_epoch_;
  header.packet_seq = packet_seq;
  const std::array<unsigned char, HEADER_LEN> wire_header = header.encode();
  const std::vector<unsigned char> body = send_key_.encrypt(
      header, plaintext, plaintext_len);
  std::vector<unsigned char> out;
  out.reserve(HEADER_LEN + body.size());
  out.insert(out.end(), wire_header.begin(), wire_header.end());
  out.insert(out.end(), body.begin(), body.end());
  ++packets_in_send_epoch_;
  return out;
}

void EpochSession::note_authenticated_ack(uint32_t ack_epoch) {
  if (ack_epoch > send_epoch_) {
    throw CryptoError("peer acknowledged a future send epoch");
  }
  if (ack_epoch > peer_ack_epoch_) peer_ack_epoch_ = ack_epoch;
}

OpenResult EpochSession::open(const unsigned char *datagram, std::size_t datagram_len) {
  if (!datagram || datagram_len < HEADER_LEN + TAG_LEN) {
    throw CryptoError("short v3 datagram");
  }

  const Header header = Header::decode(datagram, datagram_len);
  const unsigned char *body = datagram + HEADER_LEN;
  const std::size_t body_len = datagram_len - HEADER_LEN;
  std::vector<unsigned char> plaintext;

  if (header.send_epoch == receive_epoch_) {
    plaintext = receive_key_.decrypt(header, body, body_len);
  } else if (receive_epoch_ > 0
             && header.send_epoch == receive_epoch_ - 1
             && previous_receive_key_valid_) {
    plaintext = previous_receive_key_.decrypt(header, body, body_len);
  } else if (receive_epoch_ != std::numeric_limits<uint32_t>::max()
             && header.send_epoch == receive_epoch_ + 1) {
    TrafficSecret candidate_secret = receive_secret_.next();
    TrafficKey candidate_key = candidate_secret.derive_key();
    plaintext = candidate_key.decrypt(header, body, body_len);
    if (header.ack_epoch > send_epoch_) {
      throw CryptoError("peer acknowledged a future send epoch");
    }

    previous_receive_key_ = std::move(receive_key_);
    previous_receive_key_valid_ = true;
    receive_secret_ = std::move(candidate_secret);
    receive_key_ = std::move(candidate_key);
    ++receive_epoch_;
  } else {
    throw CryptoError("v3 receive epoch outside bounded window");
  }

  note_authenticated_ack(header.ack_epoch);
  return OpenResult{header, std::move(plaintext)};
}

void EpochSession::discard_previous_receive_key() {
  previous_receive_key_ = TrafficKey();
  previous_receive_key_valid_ = false;
}

std::array<unsigned char, BOOTSTRAP_LEN> generate_bootstrap() {
  std::array<unsigned char, BOOTSTRAP_LEN> out;
  if (RAND_bytes(out.data(), out.size()) != 1) {
    secure_zero(out.data(), out.size());
    throw CryptoError("secure random generation failed");
  }
  return out;
}

std::string encode_bootstrap_base64(const std::array<unsigned char, BOOTSTRAP_LEN> &bootstrap) {
  unsigned char encoded[4 * ((BOOTSTRAP_LEN + 2) / 3) + 1];
  const int len = EVP_EncodeBlock(encoded, bootstrap.data(), bootstrap.size());
  if (len != 44 || encoded[43] != '=') {
    secure_zero(encoded, sizeof(encoded));
    throw CryptoError("unexpected bootstrap base64 encoding");
  }
  std::string out(reinterpret_cast<char *>(encoded), 43);
  secure_zero(encoded, sizeof(encoded));
  return out;
}

std::array<unsigned char, BOOTSTRAP_LEN> decode_bootstrap_base64(const std::string &encoded) {
  if (encoded.size() != 43) throw CryptoError("v3 bootstrap key must be 43 base64 characters");
  std::string padded = encoded + "=";
  std::array<unsigned char, 33> decoded;
  const int len = EVP_DecodeBlock(decoded.data(),
      reinterpret_cast<const unsigned char *>(padded.data()), padded.size());
  secure_zero(&padded[0], padded.size());
  if (len != 33) {
    secure_zero(decoded.data(), decoded.size());
    throw CryptoError("invalid v3 bootstrap key");
  }
  std::array<unsigned char, BOOTSTRAP_LEN> out;
  std::copy(decoded.begin(), decoded.begin() + BOOTSTRAP_LEN, out.begin());
  secure_zero(decoded.data(), decoded.size());
  if (encode_bootstrap_base64(out) != encoded) {
    secure_zero(out.data(), out.size());
    throw CryptoError("non-canonical v3 bootstrap key");
  }
  return out;
}

InitialSecrets derive_initial_secrets(const std::array<unsigned char, BOOTSTRAP_LEN> &bootstrap) {
  static const unsigned char salt[] = "mosh-v3 bootstrap";
  std::array<unsigned char, SECRET_LEN> master =
      hkdf_extract(bootstrap.data(), bootstrap.size(), salt, sizeof(salt) - 1);
  std::array<unsigned char, SECRET_LEN> c2s =
      hkdf_expand<SECRET_LEN>(master.data(), master.size(), "mosh-v3 c2s traffic");
  std::array<unsigned char, SECRET_LEN> s2c =
      hkdf_expand<SECRET_LEN>(master.data(), master.size(), "mosh-v3 s2c traffic");
  secure_zero(master.data(), master.size());
  InitialSecrets out{TrafficSecret(c2s), TrafficSecret(s2c)};
  secure_zero(c2s.data(), c2s.size());
  secure_zero(s2c.data(), s2c.size());
  return out;
}

} // namespace MoshV3

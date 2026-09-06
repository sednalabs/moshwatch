// SPDX-License-Identifier: AGPL-3.0-or-later

#include "crypto_v3.h"

#include <cassert>
#include <cstring>
#include <iostream>

using namespace MoshV3;

static bool decrypt_fails(const TrafficKey &key, const Header &header,
                          const std::vector<unsigned char> &ct) {
  try {
    key.decrypt(header, ct.data(), ct.size());
    return false;
  } catch (const CryptoError &) {
    return true;
  }
}

int main() {
  std::array<unsigned char, BOOTSTRAP_LEN> bootstrap;
  for (std::size_t i = 0; i < bootstrap.size(); ++i) {
    bootstrap[i] = static_cast<unsigned char>(i);
  }

  const std::string b64 = encode_bootstrap_base64(bootstrap);
  assert(b64.size() == 43);
  assert(decode_bootstrap_base64(b64) == bootstrap);

  InitialSecrets secrets = derive_initial_secrets(bootstrap);
  TrafficKey c2s0 = secrets.client_to_server.derive_key();
  TrafficKey s2c0 = secrets.server_to_client.derive_key();

  Header h;
  h.send_epoch = 0;
  h.ack_epoch = 0;
  h.packet_seq = 0x0102030405060708ULL;
  const std::array<unsigned char, HEADER_LEN> wire = h.encode();
  Header roundtrip = Header::decode(wire.data(), wire.size());
  assert(roundtrip.version == 3 && roundtrip.flags == 0);
  assert(roundtrip.send_epoch == h.send_epoch);
  assert(roundtrip.ack_epoch == h.ack_epoch);
  assert(roundtrip.packet_seq == h.packet_seq);

  const char message[] = "Mosh v3 crypto prototype";
  std::vector<unsigned char> ct = c2s0.encrypt(
      h, reinterpret_cast<const unsigned char *>(message), sizeof(message) - 1);
  std::vector<unsigned char> pt = c2s0.decrypt(h, ct.data(), ct.size());
  assert(pt.size() == sizeof(message) - 1);
  assert(std::memcmp(pt.data(), message, pt.size()) == 0);

  // Directional separation: s2c material must not decrypt c2s traffic.
  assert(decrypt_fails(s2c0, h, ct));

  // The clear header is AEAD associated data.
  Header tampered_header = h;
  tampered_header.ack_epoch = 1;
  assert(decrypt_fails(c2s0, tampered_header, ct));

  // Ciphertext/tag tampering must fail.
  std::vector<unsigned char> tampered = ct;
  tampered[0] ^= 0x80;
  assert(decrypt_fails(c2s0, h, tampered));

  // Deterministic nonce changes with packet sequence under one epoch key.
  assert(c2s0.nonce(h.packet_seq) != c2s0.nonce(h.packet_seq + 1));

  // Ratcheting derives a new epoch key that cannot substitute for the old one.
  secrets.client_to_server.advance();
  TrafficKey c2s1 = secrets.client_to_server.derive_key();
  Header h1 = h;
  h1.send_epoch = 1;
  std::vector<unsigned char> ct1 = c2s1.encrypt(
      h1, reinterpret_cast<const unsigned char *>(message), sizeof(message) - 1);
  assert(decrypt_fails(c2s0, h1, ct1));
  std::vector<unsigned char> pt1 = c2s1.decrypt(h1, ct1.data(), ct1.size());
  assert(std::memcmp(pt1.data(), message, pt1.size()) == 0);

  // Epoch protocol: advance at most one unacknowledged outbound epoch.
  EpochSession client(EndpointRole::Client, derive_initial_secrets(bootstrap));
  EpochSession server(EndpointRole::Server, derive_initial_secrets(bootstrap));

  const char e0[] = "epoch zero";
  std::vector<unsigned char> delayed_e0 = client.seal(
      100, reinterpret_cast<const unsigned char *>(e0), sizeof(e0) - 1);
  OpenResult e0_open = server.open(delayed_e0.data(), delayed_e0.size());
  assert(std::memcmp(e0_open.plaintext.data(), e0, sizeof(e0) - 1) == 0);

  // Epoch zero starts eligible for the first update. Once at epoch one, the
  // sender must wait until the peer explicitly acknowledges it.
  assert(client.can_rekey_send());
  client.rekey_send();
  assert(client.send_epoch() == 1);
  assert(!client.can_rekey_send());
  bool double_rekey_blocked = false;
  try {
    client.rekey_send();
  } catch (const CryptoError &) {
    double_rekey_blocked = true;
  }
  assert(double_rekey_blocked);

  const char e1[] = "epoch one";
  std::vector<unsigned char> epoch_one = client.seal(
      101, reinterpret_cast<const unsigned char *>(e1), sizeof(e1) - 1);
  OpenResult e1_open = server.open(epoch_one.data(), epoch_one.size());
  assert(server.receive_epoch() == 1);
  assert(std::memcmp(e1_open.plaintext.data(), e1, sizeof(e1) - 1) == 0);

  // A delayed epoch-zero packet remains decryptable during the explicit
  // previous-key grace window, preserving UDP reordering tolerance.
  OpenResult delayed_open = server.open(delayed_e0.data(), delayed_e0.size());
  assert(std::memcmp(delayed_open.plaintext.data(), e0, sizeof(e0) - 1) == 0);
  server.discard_previous_receive_key();
  bool retired_old_epoch = false;
  try {
    server.open(delayed_e0.data(), delayed_e0.size());
  } catch (const CryptoError &) {
    retired_old_epoch = true;
  }
  assert(retired_old_epoch);

  // The server's next authenticated packet acknowledges client epoch one.
  const char ack[] = "ack";
  std::vector<unsigned char> ack_packet = server.seal(
      200, reinterpret_cast<const unsigned char *>(ack), sizeof(ack) - 1);
  OpenResult ack_open = client.open(ack_packet.data(), ack_packet.size());
  assert(std::memcmp(ack_open.plaintext.data(), ack, sizeof(ack) - 1) == 0);
  assert(client.peer_acknowledged_send_epoch() == 1);
  assert(client.can_rekey_send());

  // After advancing again, a long outage cannot make the sender race ahead:
  // epoch three is forbidden until epoch two is acknowledged.
  client.rekey_send();
  assert(client.send_epoch() == 2);
  assert(!client.can_rekey_send());
  bool outage_race_blocked = false;
  try {
    client.rekey_send();
  } catch (const CryptoError &) {
    outage_race_blocked = true;
  }
  assert(outage_race_blocked);

  // Cleartext epoch claims are bounded before untrusted input can request an
  // arbitrary number of HKDF steps.
  std::vector<unsigned char> future_epoch = epoch_one;
  future_epoch[2] = 0;
  future_epoch[3] = 0;
  future_epoch[4] = 0;
  future_epoch[5] = 9;
  bool future_epoch_rejected = false;
  try {
    server.open(future_epoch.data(), future_epoch.size());
  } catch (const CryptoError &) {
    future_epoch_rejected = true;
  }
  assert(future_epoch_rejected);

  // Generated bootstrap values also round-trip through the SSH text form.
  const std::array<unsigned char, BOOTSTRAP_LEN> random_bootstrap = generate_bootstrap();
  assert(decode_bootstrap_base64(encode_bootstrap_base64(random_bootstrap))
         == random_bootstrap);

  std::cout << "mosh-v3 crypto prototype: all tests passed\n";
  return 0;
}

// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HWI_PROTOBUF_H
#define BITCOIN_HWI_PROTOBUF_H

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace hwi {

//! Minimal protobuf subset used by the Trezor wire protocol (varint, bytes,
//! string, bool, nested messages, repeated varints).
class PbWriter
{
public:
    void AddVarint(int field, uint64_t value);
    void AddBool(int field, bool value);
    void AddBytes(int field, std::span<const unsigned char> value);
    void AddString(int field, std::string_view value);
    void AddMessage(int field, const std::vector<unsigned char>& nested);
    std::vector<unsigned char> Finish() const { return m_buf; }
    const std::vector<unsigned char>& Raw() const { return m_buf; }

private:
    void AddTag(int field, int wire);
    void AddRawVarint(uint64_t value);
    std::vector<unsigned char> m_buf;
};

struct PbField {
    uint64_t varint{0};
    std::vector<unsigned char> bytes;
    bool is_bytes{false};
};

using PbMap = std::multimap<int, PbField>;

PbMap PbDecode(std::span<const unsigned char> data);
std::optional<uint64_t> PbGetVarint(const PbMap& fields, int field);
std::optional<std::vector<unsigned char>> PbGetBytes(const PbMap& fields, int field);
std::optional<std::string> PbGetString(const PbMap& fields, int field);
std::vector<uint32_t> PbGetRepeatedVarint32(const PbMap& fields, int field);
std::optional<PbMap> PbGetMessage(const PbMap& fields, int field);

} // namespace hwi

#endif // BITCOIN_HWI_PROTOBUF_H

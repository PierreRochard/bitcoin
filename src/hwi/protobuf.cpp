// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hwi/protobuf.h>

#include <hwi/hwi.h>

namespace hwi {
namespace {

void WriteVarint(std::vector<unsigned char>& buf, uint64_t n)
{
    while (n >= 0x80) {
        buf.push_back(static_cast<unsigned char>((n & 0x7f) | 0x80));
        n >>= 7;
    }
    buf.push_back(static_cast<unsigned char>(n));
}

uint64_t ReadVarint(std::span<const unsigned char>& in)
{
    uint64_t result = 0;
    int shift = 0;
    while (!in.empty()) {
        const unsigned char b = in.front();
        in = in.subspan(1);
        result |= static_cast<uint64_t>(b & 0x7f) << shift;
        if ((b & 0x80) == 0) return result;
        shift += 7;
        if (shift > 63) break;
    }
    throw HWIError("Truncated protobuf varint", ErrorCode::INVALID_TX);
}

} // namespace

void PbWriter::AddRawVarint(uint64_t value)
{
    WriteVarint(m_buf, value);
}

void PbWriter::AddTag(int field, int wire)
{
    AddRawVarint((static_cast<uint64_t>(field) << 3) | static_cast<uint64_t>(wire));
}

void PbWriter::AddVarint(int field, uint64_t value)
{
    AddTag(field, 0);
    AddRawVarint(value);
}

void PbWriter::AddBool(int field, bool value)
{
    AddVarint(field, value ? 1 : 0);
}

void PbWriter::AddBytes(int field, std::span<const unsigned char> value)
{
    AddTag(field, 2);
    AddRawVarint(value.size());
    m_buf.insert(m_buf.end(), value.begin(), value.end());
}

void PbWriter::AddString(int field, std::string_view value)
{
    AddBytes(field, std::span<const unsigned char>{
                        reinterpret_cast<const unsigned char*>(value.data()), value.size()});
}

void PbWriter::AddMessage(int field, const std::vector<unsigned char>& nested)
{
    AddBytes(field, nested);
}

PbMap PbDecode(std::span<const unsigned char> data)
{
    PbMap fields;
    auto in = data;
    while (!in.empty()) {
        const uint64_t tag = ReadVarint(in);
        const int field = static_cast<int>(tag >> 3);
        const int wire = static_cast<int>(tag & 7);
        PbField val;
        if (wire == 0) {
            val.varint = ReadVarint(in);
        } else if (wire == 2) {
            const uint64_t len = ReadVarint(in);
            if (in.size() < len) {
                throw HWIError("Truncated protobuf bytes", ErrorCode::INVALID_TX);
            }
            val.bytes.assign(in.begin(), in.begin() + len);
            val.is_bytes = true;
            in = in.subspan(len);
        } else if (wire == 1) {
            if (in.size() < 8) throw HWIError("Truncated protobuf 64-bit", ErrorCode::INVALID_TX);
            in = in.subspan(8);
        } else if (wire == 5) {
            if (in.size() < 4) throw HWIError("Truncated protobuf 32-bit", ErrorCode::INVALID_TX);
            in = in.subspan(4);
        } else {
            throw HWIError("Unsupported protobuf wire type", ErrorCode::INVALID_TX);
        }
        fields.emplace(field, std::move(val));
    }
    return fields;
}

std::optional<uint64_t> PbGetVarint(const PbMap& fields, int field)
{
    auto it = fields.find(field);
    if (it == fields.end() || it->second.is_bytes) return std::nullopt;
    return it->second.varint;
}

std::optional<std::vector<unsigned char>> PbGetBytes(const PbMap& fields, int field)
{
    auto it = fields.find(field);
    if (it == fields.end() || !it->second.is_bytes) return std::nullopt;
    return it->second.bytes;
}

std::optional<std::string> PbGetString(const PbMap& fields, int field)
{
    auto bytes = PbGetBytes(fields, field);
    if (!bytes) return std::nullopt;
    return std::string(bytes->begin(), bytes->end());
}

std::vector<uint32_t> PbGetRepeatedVarint32(const PbMap& fields, int field)
{
    std::vector<uint32_t> out;
    auto range = fields.equal_range(field);
    for (auto it = range.first; it != range.second; ++it) {
        if (!it->second.is_bytes) out.push_back(static_cast<uint32_t>(it->second.varint));
    }
    return out;
}

std::optional<PbMap> PbGetMessage(const PbMap& fields, int field)
{
    auto bytes = PbGetBytes(fields, field);
    if (!bytes) return std::nullopt;
    return PbDecode(*bytes);
}

} // namespace hwi

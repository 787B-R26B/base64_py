import base64

def _encode_varint(value):
    """Encodes an integer to a variable-length byte sequence (LEB128-like)."""
    if value < 0:
        raise ValueError("Negative numbers are not supported")
    
    bytes_list = []
    while True:
        byte = value & 0x7f
        value >>= 7
        if value:
            byte |= 0x80  # Set the continuation bit
            bytes_list.append(byte)
        else:
            bytes_list.append(byte)
            break
    return bytes(bytes_list)

def _decode_varint(data, offset):
    """Decodes a single varint from data starting at offset. Returns (value, new_offset)."""
    value = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("Unexpected end of data")
        
        byte = data[offset]
        offset += 1
        
        value |= (byte & 0x7f) << shift
        if not (byte & 0x80):
            break
        shift += 7
        
    return value, offset

def encode_ids(id_list):
    # 1. 各IDをVarint形式のバイト列に変換して連結
    byte_data = bytearray()
    for val in id_list:
        byte_data.extend(_encode_varint(val))
    
    # 2. Base64エンコード (URLセーフ, パディング削除)
    encoded = base64.urlsafe_b64encode(byte_data).decode('ascii')
    return encoded.rstrip('=')

def decode_ids(encoded_str):
    # パディング(=)を復元してデコード
    padding = '=' * (-len(encoded_str) % 4)
    byte_data = base64.urlsafe_b64decode(encoded_str + padding)
    
    # バイト列から順次整数を復元
    restored_ids = []
    offset = 0
    while offset < len(byte_data):
        val, offset = _decode_varint(byte_data, offset)
        restored_ids.append(val)
        
    return restored_ids

# --- 実行テスト ---
if __name__ == "__main__":
    import sys
    
    print("数値をスペース区切りで入力してください (例: 123 456 789):")
    try:
        # Read from stdin
        input_str = input("> ").strip()
        if not input_str:
            print("入力がありません。")
            sys.exit(0)
            
        # Parse integers
        # Support space or comma separation
        input_str = input_str.replace(',', ' ')
        my_ids = [int(x) for x in input_str.split()]
        
        print(f"入力ID: {my_ids}")
        
        # Encode
        code = encode_ids(my_ids)
        print(f"エンコード結果: {code}")
        
        # Decode check
        restored = decode_ids(code)
        print(f"デコード確認: {restored}")
        
        if my_ids == restored:
            print("検証: OK")
        else:
            print("検証: FAIL")
            
    except ValueError as e:
        print(f"エラー: 数値を入力してください。({e})")
    except Exception as e:
        print(f"予期せぬエラー: {e}")
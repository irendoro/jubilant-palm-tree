BLOCK_SIZE = 16

Pi = (252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46,
        153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66,
        139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44,
        81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191,
        114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158,
        178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169,
        62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220,
        232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
        173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172,
        29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144,
        202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166,
        116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182)
reverse_Pi = (165, 45, 50, 143, 14, 48, 56, 192, 84, 230, 158, 57, 85, 126, 82, 145, 100, 3, 87, 90, 28, 96, 7,
        24, 33, 114, 168, 209, 41, 198, 164, 63, 224, 39, 141, 12, 130, 234, 174, 180, 154, 99, 73, 229,
        66, 228, 21, 183, 200, 6, 112, 157, 65, 117, 25, 201, 170, 252, 77, 191, 42, 115, 132, 213, 195,
        175, 43, 134, 167, 177, 178, 91, 70, 211, 159, 253, 212, 15, 156, 47, 155, 67, 239, 217, 121, 182,
        83, 127, 193, 240, 35, 231, 37, 94, 181, 30, 162, 223, 166, 254, 172, 34, 249, 226, 74, 188, 53,
        202, 238, 120, 5, 107, 81, 225, 89, 163, 242, 113, 86, 17, 106, 137, 148, 101, 140, 187, 119, 60,
        123, 40, 171, 210, 49, 222, 196, 95, 204, 207, 118, 44, 184, 216, 46, 54, 219, 105, 179, 20, 149,
        190, 98, 161, 59, 22, 102, 233, 92, 108, 109, 173, 55, 97, 75, 185, 227, 186, 241, 160, 133, 131,
        218, 71, 197, 176, 51, 250, 150, 111, 110, 194, 246, 80, 255, 93, 169, 142, 23, 27, 151, 125, 236,
        88, 247, 31, 251, 124, 9, 13, 122, 103, 69, 135, 220, 232, 79, 29, 78, 4, 235, 248, 243, 62, 61,
        189, 138, 136, 221, 205, 11, 19, 152, 2, 147, 128, 144, 208, 36, 52, 203, 237, 244, 206, 153, 16,
        68, 64, 146, 58, 1, 38, 18, 26, 72, 104, 245, 129, 139, 199, 214, 32, 10, 8, 0, 76, 215, 116)

l_vec = (1, 148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148)

iter_C = [None] * 32
iter_key = [None] * 10

# Функция X
def GOST_Kuz_X(a: bytes, b: bytes) -> bytes:
    return bytes([a[i] ^ b[i] for i in range(BLOCK_SIZE)])

# Функция S
def GOST_Kuz_S(in_data: bytes) -> bytes:
    out_data = bytearray(BLOCK_SIZE)
    for i in range(BLOCK_SIZE):
        data = in_data[i] if in_data[i] >= 0 else in_data[i] + 256
        out_data[i] = Pi[data]
    return bytes(out_data)

def GOST_Kuz_GF_mul(a: bytes, b: bytes) -> bytes:
    c = 0
    for _ in range(8):
        if b & 1:
            c ^= a
        hi_bit = a & 0x80  # Проверка старшего бита
        a = (a << 1) & 0xFF  # Сдвиг влево и ограничение до 8 бит
        if hi_bit:
            a ^= 0xC3
        b >>= 1
    return c

# Функция R: циклический сдвиг данных и умножение
def GOST_Kuz_R(state: bytes) -> bytes:
    a_15 = 0
    internal = bytearray(state)
    for i in reversed(range(BLOCK_SIZE)):
        if i == 0:
            internal[BLOCK_SIZE - 1] = state[i]
        else:
            internal[i - 1] = state[i]
        a_15 ^= GOST_Kuz_GF_mul(state[i], l_vec[i])
    internal[BLOCK_SIZE - 1] = a_15
    return bytes(internal)

# Функция L: многократное применение функции R
def GOST_Kuz_L(in_data: bytes) -> bytes:
    internal = in_data
    for _ in range(BLOCK_SIZE):
        internal = GOST_Kuz_R(internal)
    return internal

# Функция S^(-1)
def GOST_Kuz_reverse_S(in_data: bytes) -> bytes:
    return bytes([reverse_Pi[byte & 0xFF] for byte in in_data])

# Функция R^(-1)
def GOST_Kuz_reverse_R(state: bytes) -> bytes:
    a_0 = state[15]
    internal = bytearray(BLOCK_SIZE)
    for i in range(1, BLOCK_SIZE):
        internal[i] = state[i - 1]
        a_0 ^= GOST_Kuz_GF_mul(internal[i], l_vec[i])
    internal[0] = a_0
    return bytes(internal)

# Функция L^(-1)
def GOST_Kuz_reverse_L(in_data: bytes) -> bytes:
    internal = in_data
    for _ in range(BLOCK_SIZE):
        internal = GOST_Kuz_reverse_R(internal)
    return internal

# Функция расчета констант
def GOST_Kuz_Get_C():
    iter_num = [[0] * BLOCK_SIZE for _ in range(32)]
    for i in range(32):
        iter_num[i][0] = i + 1
        iter_C[i] = GOST_Kuz_L(bytes(iter_num[i]))

# Функция Фейстеля
def GOST_Kuz_F(in_key_1: bytes, in_key_2: bytes, iter_const: bytes) -> tuple:
    out_key_2 = in_key_1
    internal = GOST_Kuz_X(in_key_1, iter_const)
    internal = GOST_Kuz_S(internal)
    internal = GOST_Kuz_L(internal)
    out_key_1 = GOST_Kuz_X(internal, in_key_2)
    return out_key_1, out_key_2

# Функция расчета раундовых ключей
def GOST_Kuz_Expand_Key(key_1: bytes, key_2: bytes):
    GOST_Kuz_Get_C()
    iter_key[0] = key_1
    iter_key[1] = key_2
    iter12 = (key_1, key_2)
    for i in range(4):
        for j in range(8):
            iter34 = GOST_Kuz_F(iter12[0], iter12[1], iter_C[j + 8 * i])
            iter12 = iter34
        iter_key[2 * i + 2], iter_key[2 * i + 3] = iter12

# Функция шифрования блока
def GOST_Kuz_Encrypt(blk: bytes) -> bytes:
    out_blk = blk
    for i in range(9):
        out_blk = GOST_Kuz_X(iter_key[i], out_blk)
        out_blk = GOST_Kuz_S(out_blk)
        out_blk = GOST_Kuz_L(out_blk)
    out_blk = GOST_Kuz_X(out_blk, iter_key[9])
    return out_blk

# Функция расшифрования блока
def GOST_Kuz_Decrypt(blk: bytes) -> bytes:
    out_blk = blk
    out_blk = GOST_Kuz_X(out_blk, iter_key[9])
    for i in range(8, -1, -1):
        out_blk = GOST_Kuz_reverse_L(out_blk)
        out_blk = GOST_Kuz_reverse_S(out_blk)
        out_blk = GOST_Kuz_X(iter_key[i], out_blk)
    return out_blk

# Основная функция
def main():
    key_1 = bytes([0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xFF, 0xEE,
                   0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88])
    key_2 = bytes([0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32,
                   0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE])
    blk = bytes.fromhex("8899aabbccddeeff0077665544332211")

    GOST_Kuz_Expand_Key(key_1, key_2)
    encrypted_blk = GOST_Kuz_Encrypt(blk)
    print(f"Encrypted: {encrypted_blk.hex().upper()}")

    decrypted_blk = GOST_Kuz_Decrypt(encrypted_blk)
    print(f"Decrypted: {decrypted_blk.hex().upper()}")

if __name__ == "__main__":
    main()
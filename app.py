

from flask import Flask, render_template, request, jsonify
import struct

app = Flask(__name__)

DELTA = 0x9E3779B9  # Konstanta golden ratio untuk TEA

def tea_encrypt_block(v0, v1, key):
    """
    Enkripsi satu blok 64-bit menggunakan TEA.
    Input : v0, v1 (dua integer 32-bit), key (list 4 integer 32-bit)
    Output: (v0_enc, v1_enc)
    """
    k0, k1, k2, k3 = key[0], key[1], key[2], key[3]
    total = 0
    MASK = 0xFFFFFFFF  # Masker 32-bit agar tidak overflow

    for _ in range(32):  # 32 putaran (64 operasi Feistel)
        total = (total + DELTA) & MASK
        # Operasi Feistel kiri: v0 += ((v1 << 4) + k0) XOR (v1 + total) XOR ((v1 >> 5) + k1)
        v0 = (v0 + (((v1 << 4) + k0) ^ (v1 + total) ^ ((v1 >> 5) + k1))) & MASK
        # Operasi Feistel kanan: v1 += ((v0 << 4) + k2) XOR (v0 + total) XOR ((v0 >> 5) + k3)
        v1 = (v1 + (((v0 << 4) + k2) ^ (v0 + total) ^ ((v0 >> 5) + k3))) & MASK

    return v0, v1


def tea_decrypt_block(v0, v1, key):
    """
    Dekripsi satu blok 64-bit menggunakan TEA.
    Kebalikan dari tea_encrypt_block.
    """
    k0, k1, k2, k3 = key[0], key[1], key[2], key[3]
    MASK = 0xFFFFFFFF
    total = (DELTA * 32) & MASK  # Mulai dari nilai total akhir enkripsi

    for _ in range(32):
        # Urutan dibalik: dekripsi v1 dulu, baru v0
        v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + total) ^ ((v0 >> 5) + k3))) & MASK
        v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + total) ^ ((v1 >> 5) + k1))) & MASK
        total = (total - DELTA) & MASK

    return v0, v1


def tea_parse_key(key_str):
    """
    Parsing key TEA dari string hex 128-bit (32 karakter hex = 16 byte).
    Mengembalikan list 4 integer 32-bit.
    """
    key_str = key_str.strip()
    if len(key_str) != 32:
        raise ValueError("Key TEA harus 32 karakter hex (128-bit / 16 byte).")
    try:
        key_bytes = bytes.fromhex(key_str)
    except ValueError:
        raise ValueError("Key TEA harus berformat hex yang valid.")
    # Unpack menjadi 4 angka 32-bit big-endian
    return list(struct.unpack('>4I', key_bytes))


def tea_parse_iv(iv_str):
    """
    Parsing IV TEA dari string hex 64-bit (16 karakter hex = 8 byte).
    Mengembalikan tuple (iv0, iv1).
    """
    iv_str = iv_str.strip()
    if len(iv_str) != 16:
        raise ValueError("IV TEA harus 16 karakter hex (64-bit / 8 byte).")
    try:
        iv_bytes = bytes.fromhex(iv_str)
    except ValueError:
        raise ValueError("IV TEA harus berformat hex yang valid.")
    return struct.unpack('>2I', iv_bytes)


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """Menambahkan padding PKCS#7 agar data kelipatan block_size."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """Menghapus padding PKCS#7 dari data."""
    if not data:
        raise ValueError("Data kosong, tidak bisa unpad.")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > len(data):
        raise ValueError("Padding tidak valid.")
    # Verifikasi semua byte padding sama
    for b in data[-pad_len:]:
        if b != pad_len:
            raise ValueError("Padding PKCS#7 tidak valid.")
    return data[:-pad_len]



def tea_cbc_encrypt(plaintext: str, key_str: str, iv_str: str) -> str:
    """
    Enkripsi TEA mode CBC.
    CBC: Setiap blok plaintext di-XOR dengan ciphertext blok sebelumnya
         sebelum dienkripsi. Blok pertama di-XOR dengan IV.
    """
    key = tea_parse_key(key_str)
    iv0, iv1 = tea_parse_iv(iv_str)

    # Encode teks ke bytes dan tambahkan padding
    data = plaintext.encode('utf-8')
    data = pkcs7_pad(data, 8)  # TEA block size = 8 byte

    ciphertext = b''
    prev0, prev1 = iv0, iv1  # Inisialisasi dengan IV

    # Proses per blok 8 byte (2 x 32-bit)
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        b0, b1 = struct.unpack('>2I', block)

        # XOR dengan blok sebelumnya (CBC)
        b0 ^= prev0
        b1 ^= prev1

        # Enkripsi blok
        c0, c1 = tea_encrypt_block(b0, b1, key)

        ciphertext += struct.pack('>2I', c0, c1)
        prev0, prev1 = c0, c1  # Update untuk blok berikutnya

    return ciphertext.hex()


def tea_cbc_decrypt(ciphertext_hex: str, key_str: str, iv_str: str) -> str:
    """
    Dekripsi TEA mode CBC.
    """
    key = tea_parse_key(key_str)
    iv0, iv1 = tea_parse_iv(iv_str)

    try:
        ciphertext = bytes.fromhex(ciphertext_hex.strip())
    except ValueError:
        raise ValueError("Ciphertext tidak valid. Harus berformat hex.")

    if len(ciphertext) % 8 != 0:
        raise ValueError("Panjang ciphertext tidak valid (bukan kelipatan 8 byte).")

    plaintext = b''
    prev0, prev1 = iv0, iv1

    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        c0, c1 = struct.unpack('>2I', block)

        # Dekripsi blok
        d0, d1 = tea_decrypt_block(c0, c1, key)

        # XOR dengan blok ciphertext sebelumnya (CBC)
        d0 ^= prev0
        d1 ^= prev1

        plaintext += struct.pack('>2I', d0, d1)
        prev0, prev1 = c0, c1

    plaintext = pkcs7_unpad(plaintext)
    return plaintext.decode('utf-8')



def tea_ofb_encrypt(plaintext: str, key_str: str, iv_str: str) -> str:
    """
    Enkripsi TEA mode OFB (Output Feedback).
    OFB: Enkripsi IV secara berulang untuk menghasilkan keystream,
         lalu XOR keystream dengan plaintext.
    """
    key = tea_parse_key(key_str)
    iv0, iv1 = tea_parse_iv(iv_str)

    data = plaintext.encode('utf-8')
    ciphertext = b''
    o0, o1 = iv0, iv1  # Output feedback register

    i = 0
    while i < len(data):
        # Enkripsi output register untuk menghasilkan keystream
        o0, o1 = tea_encrypt_block(o0, o1, key)
        keystream = struct.pack('>2I', o0, o1)  # 8 byte keystream

        # XOR keystream dengan plaintext (hanya sebanyak sisa data)
        block = data[i:i+8]
        for j in range(len(block)):
            ciphertext += bytes([block[j] ^ keystream[j]])
        i += 8

    return ciphertext.hex()


def tea_ofb_decrypt(ciphertext_hex: str, key_str: str, iv_str: str) -> str:
    """
    Dekripsi TEA mode OFB.
    OFB bersifat simetris: proses dekripsi sama persis dengan enkripsi.
    """
    # Pada OFB, dekripsi = enkripsi (keystream sama)
    key = tea_parse_key(key_str)
    iv0, iv1 = tea_parse_iv(iv_str)

    try:
        ciphertext = bytes.fromhex(ciphertext_hex.strip())
    except ValueError:
        raise ValueError("Ciphertext tidak valid. Harus berformat hex.")

    plaintext = b''
    o0, o1 = iv0, iv1

    i = 0
    while i < len(ciphertext):
        o0, o1 = tea_encrypt_block(o0, o1, key)
        keystream = struct.pack('>2I', o0, o1)

        block = ciphertext[i:i+8]
        for j in range(len(block)):
            plaintext += bytes([block[j] ^ keystream[j]])
        i += 8

    return plaintext.decode('utf-8')


# --- Tabel permutasi DES ---

# Initial Permutation (IP)
IP = [
    58,50,42,34,26,18,10,2,  60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,  64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,   59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,  63,55,47,39,31,23,15,7
]

# Final Permutation (FP = IP^-1)
FP = [
    40,8,48,16,56,24,64,32,  39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,  37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,  35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,  33,1,41,9,49,17,57,25
]

# Expansion (E): 32-bit -> 48-bit
E = [
    32,1,2,3,4,5,   4,5,6,7,8,9,
    8,9,10,11,12,13, 12,13,14,15,16,17,
    16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32,1
]

# Permutation (P): setelah S-Box
P = [
    16,7,20,21,29,12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
]

# S-Boxes (8 kotak substitusi, masing-masing 4 baris x 16 kolom)
S_BOXES = [
    # S1
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
     [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
     [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
     [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    # S2
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
     [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
     [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
     [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    # S3
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
     [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
     [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
     [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    # S4
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
     [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
     [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
     [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    # S5
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
     [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
     [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
     [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    # S6
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
     [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
     [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
     [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    # S7
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
     [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
     [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
     [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    # S8
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
     [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
     [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
     [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
]

# Permuted Choice 1 (PC1) untuk Key Schedule
PC1 = [
    57,49,41,33,25,17,9,  1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,  19,11,3,60,52,44,36,
    63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,  21,13,5,28,20,12,4
]

# Permuted Choice 2 (PC2) untuk Key Schedule
PC2 = [
    14,17,11,24,1,5,  3,28,15,6,21,10,
    23,19,12,4,26,8,  16,7,27,20,13,2,
    41,52,31,37,47,55, 30,40,51,45,33,48,
    44,49,39,56,34,53, 46,42,50,36,29,32
]

# Jumlah pergeseran kiri per ronde Key Schedule
SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]


def des_permute(bits, table):
    """Permutasi bit berdasarkan tabel."""
    return [bits[table[i] - 1] for i in range(len(table))]


def des_xor(a, b):
    """XOR dua list bit."""
    return [x ^ y for x, y in zip(a, b)]


def des_left_shift(bits, n):
    """Rotasi kiri sebesar n bit."""
    return bits[n:] + bits[:n]


def des_generate_subkeys(key_bytes):
    """
    Menghasilkan 16 subkunci dari kunci DES 8 byte (64-bit, 56-bit efektif).
    """
    # Konversi key ke list bit
    key_bits = []
    for byte in key_bytes:
        for i in range(7, -1, -1):
            key_bits.append((byte >> i) & 1)

    # PC1: Reduksi 64-bit -> 56-bit
    key56 = des_permute(key_bits, PC1)
    C, D = key56[:28], key56[28:]

    subkeys = []
    for i in range(16):
        # Rotasi kiri C dan D
        C = des_left_shift(C, SHIFTS[i])
        D = des_left_shift(D, SHIFTS[i])
        # PC2: Reduksi 56-bit -> 48-bit subkunci
        CD = C + D
        subkeys.append(des_permute(CD, PC2))

    return subkeys


def des_f_function(R, subkey):
    """
    Fungsi F dalam satu ronde DES.
    R (32-bit) -> Expansion (48-bit) -> XOR subkey -> S-Box -> Permutation -> 32-bit
    """
    # Expansion: 32-bit -> 48-bit
    expanded = des_permute(R, E)

    # XOR dengan subkunci
    xored = des_xor(expanded, subkey)

    # Substitusi S-Box: 48-bit -> 32-bit
    result = []
    for i in range(8):
        block = xored[i*6:(i+1)*6]
        # Baris: bit pertama dan terakhir
        row = (block[0] << 1) | block[5]
        # Kolom: 4 bit tengah
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        val = S_BOXES[i][row][col]
        # Konversi nilai 4-bit ke list bit
        for j in range(3, -1, -1):
            result.append((val >> j) & 1)

    # Permutasi P
    return des_permute(result, P)


def des_encrypt_block(block_bytes, subkeys):
    """
    Enkripsi satu blok 8 byte menggunakan DES.
    """
    bits = []
    for byte in block_bytes:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    # Initial Permutation
    bits = des_permute(bits, IP)
    L, R = bits[:32], bits[32:]

    # 16 Ronde Feistel
    for i in range(16):
        L_new = R
        R_new = des_xor(L, des_f_function(R, subkeys[i]))
        L, R = L_new, R_new

    # Gabungkan R dan L (dibalik setelah ronde terakhir)
    combined = R + L

    # Final Permutation
    final_bits = des_permute(combined, FP)

    # Konversi bit -> bytes
    result = bytearray(8)
    for i in range(8):
        for j in range(8):
            result[i] = (result[i] << 1) | final_bits[i*8 + j]
    return bytes(result)


def des_decrypt_block(block_bytes, subkeys):
    """
    Dekripsi satu blok 8 byte menggunakan DES.
    Sama seperti enkripsi tetapi subkunci dibalik urutannya.
    """
    return des_encrypt_block(block_bytes, subkeys[::-1])


def des_parse_key(key_str):
    """
    Parsing key DES dari string hex 16 karakter (8 byte / 64-bit).
    """
    key_str = key_str.strip()
    if len(key_str) != 16:
        raise ValueError("Key DES harus 16 karakter hex (64-bit / 8 byte).")
    try:
        return bytes.fromhex(key_str)
    except ValueError:
        raise ValueError("Key DES harus berformat hex yang valid.")


def des_parse_iv(iv_str):
    """
    Parsing IV DES dari string hex 16 karakter (8 byte / 64-bit).
    """
    iv_str = iv_str.strip()
    if len(iv_str) != 16:
        raise ValueError("IV DES harus 16 karakter hex (64-bit / 8 byte).")
    try:
        return bytes.fromhex(iv_str)
    except ValueError:
        raise ValueError("IV DES harus berformat hex yang valid.")



def des_cbc_encrypt(plaintext: str, key_str: str, iv_str: str) -> str:
    """Enkripsi DES mode CBC."""
    key_bytes = des_parse_key(key_str)
    iv = des_parse_iv(iv_str)
    subkeys = des_generate_subkeys(key_bytes)

    data = plaintext.encode('utf-8')
    data = pkcs7_pad(data, 8)

    ciphertext = b''
    prev_block = iv

    for i in range(0, len(data), 8):
        block = data[i:i+8]
        # XOR plaintext dengan blok sebelumnya (CBC)
        xored = bytes(a ^ b for a, b in zip(block, prev_block))
        enc_block = des_encrypt_block(xored, subkeys)
        ciphertext += enc_block
        prev_block = enc_block

    return ciphertext.hex()


def des_cbc_decrypt(ciphertext_hex: str, key_str: str, iv_str: str) -> str:
    """Dekripsi DES mode CBC."""
    key_bytes = des_parse_key(key_str)
    iv = des_parse_iv(iv_str)
    subkeys = des_generate_subkeys(key_bytes)

    try:
        ciphertext = bytes.fromhex(ciphertext_hex.strip())
    except ValueError:
        raise ValueError("Ciphertext tidak valid. Harus berformat hex.")

    if len(ciphertext) % 8 != 0:
        raise ValueError("Panjang ciphertext tidak valid (bukan kelipatan 8 byte).")

    plaintext = b''
    prev_block = iv

    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        dec_block = des_decrypt_block(block, subkeys)
        # XOR dengan blok ciphertext sebelumnya
        xored = bytes(a ^ b for a, b in zip(dec_block, prev_block))
        plaintext += xored
        prev_block = block

    plaintext = pkcs7_unpad(plaintext)
    return plaintext.decode('utf-8')



def des_ofb_encrypt(plaintext: str, key_str: str, iv_str: str) -> str:
    """Enkripsi DES mode OFB."""
    key_bytes = des_parse_key(key_str)
    iv = des_parse_iv(iv_str)
    subkeys = des_generate_subkeys(key_bytes)

    data = plaintext.encode('utf-8')
    ciphertext = b''
    output_block = iv  # Output feedback register

    i = 0
    while i < len(data):
        # Enkripsi output register untuk keystream
        output_block = des_encrypt_block(output_block, subkeys)
        block = data[i:i+8]
        # XOR keystream dengan plaintext
        enc = bytes(a ^ b for a, b in zip(block, output_block[:len(block)]))
        ciphertext += enc
        i += 8

    return ciphertext.hex()


def des_ofb_decrypt(ciphertext_hex: str, key_str: str, iv_str: str) -> str:
    """Dekripsi DES mode OFB (identik dengan enkripsi OFB)."""
    key_bytes = des_parse_key(key_str)
    iv = des_parse_iv(iv_str)
    subkeys = des_generate_subkeys(key_bytes)

    try:
        ciphertext = bytes.fromhex(ciphertext_hex.strip())
    except ValueError:
        raise ValueError("Ciphertext tidak valid. Harus berformat hex.")

    plaintext = b''
    output_block = iv

    i = 0
    while i < len(ciphertext):
        output_block = des_encrypt_block(output_block, subkeys)
        block = ciphertext[i:i+8]
        dec = bytes(a ^ b for a, b in zip(block, output_block[:len(block)]))
        plaintext += dec
        i += 8

    return plaintext.decode('utf-8')


def vigenere_encrypt(plaintext: str, key: str) -> str:
    """
    Enkripsi Vigenere Cipher.
    Setiap huruf plaintext digeser maju sebesar nilai huruf key (A=0, B=1, ...).
    Karakter non-huruf dibiarkan apa adanya.
    """
    # Validasi: key harus berisi huruf saja
    key_clean = ''.join(c for c in key if c.isalpha())
    if not key_clean:
        raise ValueError("Key Vigenere harus berisi minimal satu huruf.")

    key_upper = key_clean.upper()
    result = []
    key_idx = 0  # Indeks key hanya bergerak untuk karakter huruf

    for char in plaintext:
        if char.isalpha():
            shift = ord(key_upper[key_idx % len(key_upper)]) - ord('A')
            if char.isupper():
                # Huruf besar: geser dalam A-Z
                enc = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                # Huruf kecil: geser dalam a-z
                enc = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            result.append(enc)
            key_idx += 1
        else:
            # Karakter bukan huruf: tetap apa adanya
            result.append(char)

    return ''.join(result)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """
    Dekripsi Vigenere Cipher.
    Kebalikan dari enkripsi: setiap huruf digeser mundur.
    """
    key_clean = ''.join(c for c in key if c.isalpha())
    if not key_clean:
        raise ValueError("Key Vigenere harus berisi minimal satu huruf.")

    key_upper = key_clean.upper()
    result = []
    key_idx = 0

    for char in ciphertext:
        if char.isalpha():
            shift = ord(key_upper[key_idx % len(key_upper)]) - ord('A')
            if char.isupper():
                # Geser mundur untuk dekripsi
                dec = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                dec = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            result.append(dec)
            key_idx += 1
        else:
            result.append(char)

    return ''.join(result)


@app.route('/')
def index():
    """Halaman utama."""
    return render_template('index.html')


@app.route('/process', methods=['POST'])
def process():
    """
    Endpoint utama untuk memproses enkripsi/dekripsi.
    Menerima data JSON dan mengembalikan hasil dalam JSON.
    """
    data = request.get_json()

    action    = data.get('action', '').strip()     # 'encrypt' atau 'decrypt'
    method    = data.get('method', '').strip()     # Metode yang dipilih
    text      = data.get('text', '').strip()       # Teks input
    key       = data.get('key', '').strip()        # Kunci
    iv        = data.get('iv', '').strip()         # Initialization Vector

    if not text:
        return jsonify({'error': 'Teks input tidak boleh kosong.'}), 400
    if not key:
        return jsonify({'error': 'Key/kunci tidak boleh kosong.'}), 400

    methods_need_iv = ['TEA-CBC', 'TEA-OFB', 'DES-CBC', 'DES-OFB']
    if method in methods_need_iv and not iv:
        return jsonify({'error': f'IV diperlukan untuk metode {method}.'}), 400

    try:
        result = None

        if method == 'TEA-CBC':
            if action == 'encrypt':
                result = tea_cbc_encrypt(text, key, iv)
            else:
                result = tea_cbc_decrypt(text, key, iv)

        elif method == 'TEA-OFB':
            if action == 'encrypt':
                result = tea_ofb_encrypt(text, key, iv)
            else:
                result = tea_ofb_decrypt(text, key, iv)

        elif method == 'DES-CBC':
            if action == 'encrypt':
                result = des_cbc_encrypt(text, key, iv)
            else:
                result = des_cbc_decrypt(text, key, iv)

        elif method == 'DES-OFB':
            if action == 'encrypt':
                result = des_ofb_encrypt(text, key, iv)
            else:
                result = des_ofb_decrypt(text, key, iv)

        elif method == 'Vigenere':
            if action == 'encrypt':
                result = vigenere_encrypt(text, key)
            else:
                result = vigenere_decrypt(text, key)

        else:
            return jsonify({'error': 'Metode tidak dikenal.'}), 400

        return jsonify({'result': result, 'action': action, 'method': method})

    except ValueError as e:
        # Error dari validasi (key salah, padding salah, dll)
        return jsonify({'error': str(e)}), 400
    except UnicodeDecodeError:
        return jsonify({'error': 'Gagal mendekode hasil. Pastikan key, IV, dan ciphertext benar.'}), 400
    except Exception as e:
        return jsonify({'error': f'Terjadi kesalahan: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)

# CipherLab — Aplikasi Enkripsi & Dekripsi
## Tugas Mata Kuliah Keamanan Sistem

---

## Struktur Project

```
crypto_app/
├── app.py                  # Backend Flask + semua algoritma kriptografi
├── requirements.txt        # Daftar dependensi Python
├── templates/
│   └── index.html          # Halaman utama (HTML)
└── static/
    └── style.css           # Stylesheet (CSS)
```

---

## Fitur

| Algoritma     | Mode | Key         | IV          |
|---------------|------|-------------|-------------|
| TEA           | CBC  | 32 hex char | 16 hex char |
| TEA           | OFB  | 32 hex char | 16 hex char |
| DES           | CBC  | 16 hex char | 16 hex char |
| DES           | OFB  | 16 hex char | 16 hex char |
| Vigenere      | —    | Huruf bebas | Tidak perlu |

---

## Cara Menjalankan

### 1. Pastikan Python 3.8+ terinstal
```bash
python --version
```

### 2. (Opsional) Buat virtual environment
```bash
python -m venv venv

# Windows:
venv\Scripts\activate

# Mac/Linux:
source venv/bin/activate
```

### 3. Install dependensi
```bash
pip install -r requirements.txt
```

### 4. Jalankan aplikasi
```bash
python app.py
```

### 5. Buka browser
```
http://localhost:5000
```

---

## Contoh Penggunaan

### TEA-CBC Enkripsi
- **Teks**: `Hello, Dunia!`
- **Key**: `0123456789abcdef0123456789abcdef`
- **IV**: `0102030405060708`
- Klik **Enkripsi**

### TEA-CBC Dekripsi
- **Teks**: *(hasil hex dari enkripsi di atas)*
- **Key**: *(key yang sama)*
- **IV**: *(IV yang sama)*
- Klik **Dekripsi**

### Vigenere Enkripsi
- **Teks**: `Keamanan Sistem`
- **Key**: `KUNCI`
- Klik **Enkripsi**

---

## Catatan Teknis

- Semua algoritma diimplementasikan **manual** tanpa library kriptografi (PyCryptodome, cryptography, dll.).
- Ciphertext ditampilkan dalam format **hexadecimal**.
- TEA & DES menggunakan padding **PKCS#7**.
- Mode **OFB** bersifat self-synchronizing: enkripsi = dekripsi secara simetris.
- DES menggunakan implementasi penuh: IP, Key Schedule (PC1/PC2), 16 ronde Feistel, S-Box, F-function, FP.

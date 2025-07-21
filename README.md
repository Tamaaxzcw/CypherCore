# CypherCore by Tamaaxzcw

Koleksi pustaka kriptografi lintas-bahasa yang aman, modern, dan kompatibel, menyediakan enkripsi dan dekripsi menggunakan **AES-256-GCM** dan **PBKDF2**.

## ✨ Fitur Utama

* **Keamanan Terdepan**: Menggunakan AES-256-GCM untuk enkripsi terotentikasi.
* **Derivasi Kunci yang Kuat**: Menggunakan PBKDF2 untuk melindungi dari serangan brute-force terhadap *secret key*.
* **Kompatibilitas Penuh**: Enkripsi di satu bahasa, dekripsi di bahasa lain. Format outputnya adalah `Base64(salt:iv:tag:ciphertext)`.
* **Implementasi**: Tersedia dalam JavaScript, TypeScript, Python, Java, dan Go.

## ✍️ Author

* **Tamaaxzcw**
* **GitHub**: `https://github.com/Tamaaxzcw`

## ⚠️ Peringatan Keamanan

Jaga kerahasiaan `secretKey` Anda. Jangan pernah menyimpannya secara *hardcode* di dalam kode sisi klien atau di repositori publik. Gunakan variabel lingkungan (*environment variables*) untuk manajemen kunci yang aman.

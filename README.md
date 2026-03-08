# VANGUARD ⚔️

**VANGUARD** adalah _Enterprise-grade Security Sentinel_ berperforma tinggi yang dirancang untuk mengamankan ekosistem PHP modern. Meskipun berakar pada **Laravel**, VANGUARD kini mendukung berbagai framework besar dengan logika pemindaian cerdas yang menggabungkan aturan keamanan umum (OWASP) dan spesifik framework.

Dibangun dengan **Go**, VANGUARD memanfaatkan mesin regex yang dipre-kompilasi untuk kecepatan maksimal, antarmuka **Bubbletea TUI** yang interaktif, dan laporan **Glassmorphism** yang premium.

---

## 🏗️ Dukungan Multi-Framework

VANGUARD secara otomatis mendeteksi framework proyek Anda dan menerapkan aturan keamanan yang relevan:

- **Laravel & Lumen:** Audit komprehensif untuk Eloquent, Blade, Sanctum, dan Artisan.
- **Symfony:** Keamanan ESI, serialisasi, konfigurasi Profiler, dan keamanan kernel.
- **WordPress:** Deteksi `wpdb` yang tidak aman, validasi Nonce, dan proteksi AJAX.
- **CodeIgniter (2, 3, 4):** Penanganan input, proteksi XSS bawaan, dan keamanan database.
- **Yii2:** Deteksi eksposur Gii, validasi cookie, dan konfigurasi RBAC.
- **CakePHP:** Audit SecurityComponent, proteksi Mass Assignment, dan Auth.

---

## ⚡ Fitur Utama

- **Mesin Berperforma Tinggi:** Ditulis dalam Go dengan optimasi pre-kompilasi regex untuk pemindaian instan pada codebase besar.
- **Audit Standar Industri:** Semua pola keamanan diaudit terhadap **OWASP Top 10**, **CWE**, dan **NIST**.
- **Logika Aturan Berlapis:** Menggabungkan `Common Rules` (Injection, SSRF, Deserialization) dengan `Framework Specific Rules`.
- **Vanguard Defense Rating (VDR):** Penilaian keamanan cerdas (0-100) berdasarkan profil risiko proyek Anda.
- **Premium Reporting:** Output dalam format TUI (interaktif), HTML (modern), JSON, SARIF, dan Markdown.

---

## 🛠️ Instalasi

Pastikan Anda telah menginstal Go (versi 1.21 atau lebih baru).

```bash
go install github.com/haliminurja/vanguard@latest
```

---

## 🏁 Penggunaan Cepat

### 1. Inisialisasi

Buat konfigurasi awal `vanguard.yaml` di root proyek Anda.

```bash
vanguard init
```

### 2. Jalankan Pemindaian

```bash
# Memindai seluruh proyek secara otomatis
vanguard scan .

# Pemindaian spesifik dengan output HTML
vanguard scan . --output html

# Gagal otomatis di CI jika ditemukan celah 'high' atau 'critical'
vanguard scan . --fail-on high
```

---

## 🤖 Integrasi CI/CD

VANGUARD dirancang untuk menjadi bagian integral dari pipeline Anda:

- **GitHub Actions:** Gunakan output SARIF untuk integrasi langsung dengan GitHub Code Scanning.
- **GitLab:** Integrasi mudah dengan format JSON.
- **Pre-commit Hooks:** Jalankan VANGUARD sebelum setiap commit untuk mencegah kebocoran rahasia (secrets).

---

## 📝 Konfigurasi (`vanguard.yaml`)

```yaml
# Tingkat keparahan minimum (info, low, medium, high, critical)
severity: medium

scanners:
  # Folder yang diabaikan dari pemindaian
  ignore_dirs: ["vendor", "node_modules", "storage", "public", "tests"]

ignore:
  # Abaikan path spesifik
  paths:
    - "database/factories/**"
  # Abaikan Rule ID tertentu
  rules:
    - "COMMON-XSS-01"
```

---

## 🌓 Laporan & Antarmuka

- **TUI:** Pengalaman terminal interaktif dengan navigasi temuan real-time.
- **HTML (Cyber-Glass):** Laporan statis premium dengan grafik responsif dan visualisasi ranking pertahanan.
- **SARIF/JSON:** Standar industri untuk interoperabilitas tool keamanan.

---

Dibuat dengan ❤️ untuk keamanan web oleh [Ahmad Halimi](https://github.com/haliminurja/vanguard)

# VANGUARD ⚔️

**VANGUARD** adalah _Security Sentinel_ modern yang dirancang khusus untuk ekosistem **Laravel**. VANGUARD membantu pengembang mendeteksi kerentanan keamanan, kebocoran data (secrets), dan kesalahan konfigurasi secara otomatis di dalam kode sumber PHP, Blade, dan konfigurasi Laravel Anda.

Dibangun menggunakan bahasa pemrograman **Go** dengan antarmuka **Bubbletea TUI** yang interaktif dan _Defense Report_ bergaya _Glassmorphism_.

---

## 🚀 Fitur Khusus Laravel

- **Eloquent Security Audit:** Mendeteksi penggunaan `$guarded = []`, hilangnya `$hidden` pada field sensitif (seperti password), dan _mass assignment_ ilegal.
- **Blade Protection Scan:** Memastikan setiap form non-GET memiliki direktif `@csrf` dan mendeteksi potensi XSS pada penggunaan `{!! !!}` yang tidak aman.
- **Route & Controller Guard:** Identifikasi penggunaan `Route::any()`, validasi input yang terlewat pada queued jobs, dan masalah otorisasi pada broadcast channels.
- **Sanctum & API Security:** Memeriksa konfigurasi token, CORS, dan header keamanan yang krusial untuk aplikasi modern.
- **Integrasi Artisan:** Mudah dijalankan sebagai bagian dari workflow pengembangan Laravel Anda.
- **Vanguard Defense Rating (VDR):** Skor profil risiko keamanan proyek Laravel Anda (0-100).

---

## 🛠️ Instalasi

Pastikan Anda telah menginstal Go (versi 1.21 atau lebih baru).

```bash
go install github.com/haliminurja/vanguard@latest
```

---

## 🏁 Alur Kerja Penggunaan

### 1. Inisialisasi Proyek Laravel

Siapkan berkas konfigurasi `vanguard.yaml` di direktori utama proyek Laravel Anda.

```bash
vanguard init
```

Perintah ini akan membuat `vanguard.yaml` dengan aturan bawaan yang sudah dioptimalkan untuk struktur folder Laravel (`app`, `config`, `routes`, `resources/views`).

### 2. Jalankan Pemindaian (Scan)

VANGUARD mendukung berbagai parameter untuk menyesuaikan proses pemindaian pada folder proyek atau modul spesifik.

#### Contoh Penggunaan

```bash
# Memindai seluruh proyek Laravel saat ini
vanguard scan .

# Memindai folder Controller saja
vanguard scan ./app/Http/Controllers

# Memindai view Blade untuk celah XSS/CSRF
vanguard scan ./resources/views

# Menghasilkan laporan HTML dengan skor VDR
vanguard scan . --output html
```

#### Opsi Pemindaian (Flags)

- **`--fail-on [severity]`**: Gagal proses (exit code 1) jika ada temuan tingkat `medium`, `high`, atau `critical`. Cocok untuk CI/CD pipeline.
- **`-o`, `--output`**: Format laporan (`tui`, `html`, `json`, `sarif`, `markdown`).
- **`-v`, `--verbose`**: Detail log proses pemindaian.

---

### 3. Konfigurasi Lanjutan (`vanguard.yaml`)

Sesuaikan perilaku VANGUARD melalui `vanguard.yaml`:

```yaml
# Tingkat keparahan minimum (info, low, medium, high, critical)
severity: info

scanners:
  # Folder standar Laravel yang diabaikan (sudah include default)
  ignore_dirs: ["vendor", "node_modules", "storage", "public", "tests"]

ignore:
  # Mengabaikan file hasil generate atau file test spesifik
  paths:
    - "database/factories/**"
    - "**/mock_*.go"
  # Mengabaikan Rule ID tertentu
  rules:
    - "LARAVEL-014" # Contoh: Abaikan cek Model::unguard()

output:
  formats: ["tui", "html", "markdown"]
```

### 4. Hasil Temuan & Laporan

- **TUI (Interactive):** Navigasi temuan secara langsung di terminal Anda.
- **HTML (Glassmorphism):** Laporan premium yang ramah untuk tim security atau manajemen.
- **JSON/SARIF:** Integrasi dengan GitLab/GitHub Code Quality atau alat CI lainnya.
- **Markdown:** Ringkasan cepat untuk dimasukkan ke dalam dokumentasi internal.

---

## 🤖 Integrasi CI/CD

- **GitHub Actions:** `vanguard ci github`
- **GitLab CI:** `vanguard ci gitlab`

---

## 📝 Konfigurasi

Anda dapat menyesuaikan pemindaian melalui `vanguard.yaml`:

```yaml
severity: info
scanners:
  ignore_dirs: ["vendor", "node_modules", "tests"]
ignore:
  paths:
    - "tests/*"
```

---

Dibuat dengan ❤️ oleh [Ahmad Halimi](https://github.com/haliminurja/vanguard)

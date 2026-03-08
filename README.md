# VANGUARD ⚔️

**VANGUARD** adalah _Security Sentinel_ modern yang dirancang khusus untuk mendeteksi kerentanan keamanan, rahasia (secrets), dan kesalahan konfigurasi dalam kode sumber Anda. Dibangun menggunakan bahasa pemrograman **Go** dengan antarmuka **Bubbletea TUI** yang interaktif dan _Defense Report_ bergaya _Glassmorphism_.

- **Vanguard Defense Rating (VDR):** Sistem penilaian keamanan cerdas yang memberikan skor dari 0 hingga 100 berdasarkan profil risiko proyek Anda.

## 🚀 Fitur Utama

- **Inisialisasi Cepat:** Siapkan konfigurasi keamanan proyek hanya dalam satu perintah.
- **Pemindaian Interaktif:** Antarmuka TUI yang intuitif memberikan umpan balik langsung saat pemindaian berjalan.
- **Berbagai Format Laporan:** Mendukung TUI, HTML, Markdown, JSON, dan SARIF.
- **Integrasi CI/CD:** Mudah diintegrasikan ke dalam alur kerja GitHub Actions atau GitLab CI.
- **Git Hooks:** Otomatisasi pemeriksaan keamanan sebelum proses _commit_.

---

## 🛠️ Instalasi

Pastikan Anda telah menginstal Go (versi 1.21 atau lebih baru).

```bash
go install github.com/haliminurja/vanguard@latest
```

---

## 🏁 Alur Kerja Penggunaan

### 1. Inisialisasi Proyek (Awal)

Langkah pertama adalah menyiapkan berkas konfigurasi `vanguard.yaml` di direktori utama proyek Anda.

```bash
vanguard init
```

Perintah ini akan:

- Membuat berkas `vanguard.yaml` dengan pengaturan bawaan.
- Memasang _Git pre-commit hook_ (jika direktori `.git` ditemukan) untuk mencegah _commit_ kode yang tidak aman.

### 2. Jalankan Pemindaian (Scan)

Setelah diinisialisasi, Anda dapat mulai memindai proyek untuk mencari celah keamanan. VANGUARD mendukung berbagai parameter untuk menyesuaikan proses pemindaian.

#### Contoh Penggunaan Dasar

```bash
# Memindai direktori saat ini
vanguard scan .
```

#### Opsi Pemindaian (Flags)

Anda dapat menyesuaikan pemindaian menggunakan flags berikut:

- **Target Path:** Tentukan folder, file lokal, atau repositori remote yang ingin dipindai.

  ```bash
  # Scan path relatif
  vanguard scan ./internal/api

  # Scan path absolut
  vanguard scan "C:\Projects\my-awesome-app"

  # Scan repositori Git remote
  vanguard scan https://github.com/username/repository.git
  ```

- **Output Mode (`-o`, `--output`):** Pilih format laporan (default: `tui`). Gunakan koma untuk beberapa format sekaligus.

  ```bash
  # Tampilan interaktif (TUI)
  vanguard scan . --output tui

  # Menghasilkan berbagai file laporan (HTML, JSON, Markdown, SARIF)
  vanguard scan . --output html,json,markdown
  ```

- **Severity Filtering (`--fail-on`):** Gagal proses (exit code 1) jika ditemukan kerentanan dengan tingkat keparahan tertentu ke atas.
  ```bash
  # Gagal jika ada temuan 'high' atau 'critical'
  vanguard scan . --fail-on high
  ```
- **Verbose Output (`-v`, `--verbose`):** Menampilkan log detail proses pemindaian.
  ```bash
  vanguard scan . --verbose
  ```

---

### 3. Konfigurasi Lanjutan (`vanguard.yaml`)

Gunakan berkas `vanguard.yaml` untuk kontrol yang lebih presisi.

```yaml
# Tingkat keparahan minimum yang dilaporkan (info, low, medium, high, critical)
severity: info

scanners:
  # Mengabaikan folder tertentu secara global
  ignore_dirs: ["vendor", "node_modules", "tests"]
  # Mematikan scanner tertentu (misal: rules-scanner, dependency-scanner)
  # disable: ["dependency-scanner"]

ignore:
  # Mengabaikan path file tertentu (mendukung glob pattern)
  paths:
    - "tests/**"
    - "**/mock_*.go"
  # Mengabaikan Rule ID tertentu secara global
  rules:
    - "VND-FL-001"

output:
  # Lokasi penyimpanan laporan (default: direktori saat ini)
  # dir: "./security-reports"
  formats: ["tui", "html", "markdown"]
```

### 4. Hasil Temuan (Laporan)

Setelah pemindaian selesai, VANGUARD akan menampilkan ringkasan temuan. Jika format file laporan dipilih, berkas akan dihasilkan di direktori proyek Anda.

- **TUI (Interactive):** Antarmuka terminal bergaya modern untuk navigasi temuan secara langsung.
- **HTML:** Laporan statis dengan desain _Glassmorphism_ yang cocok untuk presentasi.
- **JSON/SARIF:** Format standar untuk integrasi dengan alat audit keamanan atau IDE.
- **Markdown:** Ringkasan temuan yang ramah untuk dokumentasi GitHub/GitLab.

---

## 🤖 Integrasi CI/CD

VANGUARD memudahkan penyiapan otomatisasi keamanan di repositori Anda:

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

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

Setelah diinisialisasi, Anda dapat mulai memindai proyek untuk mencari celah keamanan.

```bash
vanguard scan .
```

Anda juga dapat mengatur tingkat keparahan minimum atau format keluaran:

```bash
# Scan dengan format HTML
vanguard scan . --output html

# Scan dan gagal proses jika ada temuan tingkat 'high'
vanguard scan . --fail-on high
```

### 3. Hasil Temuan (Akhir)

Setelah pemindaian selesai, VANGUARD akan menampilkan ringkasan temuan. Jika Anda menggunakan format laporan lain, berkas laporan akan dihasilkan di direktori proyek Anda.

- **TUI:** Tampilan interaktif langsung di terminal.
- **HTML/Markdown:** Cocok untuk dokumentasi atau tinjauan tim.
- **JSON/SARIF:** Ideal untuk integrasi dengan alat analisis statis lainnya.

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

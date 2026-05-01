# Draf Artikel Jurnal

## Perancangan dan Evaluasi Awal Framework-Aware Static Security Scanner untuk Aplikasi PHP Multi-Framework Berbasis OWASP, CWE, dan OSV

**Nama Penulis**  
Program Magister Sistem Informasi  
**Email:** isi-email-anda

### Abstrak
Keamanan aplikasi web menjadi isu strategis dalam pengembangan sistem informasi karena celah pada level source code, konfigurasi, dan dependensi dapat langsung memengaruhi kerahasiaan, integritas, serta ketersediaan layanan. Tantangan tersebut semakin kompleks pada ekosistem PHP modern yang berkembang dalam berbagai framework, seperti Laravel, Symfony, WordPress, CodeIgniter, Yii2, dan CakePHP. Banyak alat *static application security testing* (SAST) masih mengandalkan pendekatan generik sehingga kurang adaptif terhadap karakteristik masing-masing framework. Penelitian ini bertujuan merancang artefak berupa *framework-aware static security scanner* untuk aplikasi PHP multi-framework yang mampu meningkatkan relevansi deteksi kerentanan melalui pemanfaatan rule umum dan rule spesifik framework. Penelitian menggunakan pendekatan *Design Science Research* dengan tahapan identifikasi masalah, perumusan tujuan, desain dan pengembangan artefak, demonstrasi, serta evaluasi. Artefak yang dihasilkan, yaitu VANGUARD, dibangun menggunakan Go dan mengintegrasikan deteksi konteks framework, pemindaian source code berbasis aturan, pemeriksaan kerentanan dependensi berbasis OSV, histori scan, perbandingan hasil dengan scan sebelumnya, dan pelaporan dalam format TUI, JSON, SARIF, HTML, serta Markdown. Implementasi saat ini mencakup 464 rule keamanan pada 152 berkas YAML, terdiri atas 98 rule umum dan 366 rule spesifik framework. Evaluasi dilakukan melalui tiga lapis, yaitu validasi fungsional internal, uji *workspace scan* pada repositori penelitian, dan uji fixture PHP terkontrol yang mencakup 12 skenario rentan serta 12 skenario aman. Hasil evaluasi menunjukkan bahwa 97 *test case* internal lulus, seluruh 12 skenario kerentanan pada fixture positif berhasil terdeteksi, seluruh 12 skenario aman tidak menghasilkan temuan, precision, recall, specificity, accuracy, dan F1-score pada dataset terkontrol masing-masing sebesar 100%, rata-rata waktu pemindaian fixture positif sebesar 32.8322 ms, dan pembandingan antara fixture Laravel yang dikenali konteksnya dengan salinan kode yang sama tanpa metadata framework menghasilkan 6 temuan berbanding 0 temuan. Selain itu, scan pada root *workspace* menghasilkan 12 temuan yang seluruhnya berasal dari folder `research_fixtures`, sehingga sekaligus memperlihatkan bahwa artefak saat ini bekerja paling tepat ketika satu target scan merepresentasikan satu konteks proyek dominan. Kontribusi penelitian ini terletak pada penyusunan model *framework-aware static security scanning* yang ringan, terstruktur, dan telah menunjukkan efek deteksi yang nyata pada evaluasi awal. Penelitian ini diharapkan memperkaya kajian keamanan aplikasi dalam bidang Sistem Informasi dan menyediakan artefak praktis untuk audit keamanan aplikasi PHP modern.

**Kata kunci:** keamanan aplikasi web, PHP, static application security testing, multi-framework, source code analysis, DevSecOps

### Abstract
Web application security is a strategic issue in information systems development because vulnerabilities at the source-code, configuration, and dependency levels may directly affect confidentiality, integrity, and service availability. This challenge becomes more complex in the modern PHP ecosystem, which spans multiple frameworks such as Laravel, Symfony, WordPress, CodeIgniter, Yii2, and CakePHP. Many static application security testing (SAST) tools still rely on generic approaches and are therefore less adaptive to framework-specific characteristics. This study aims to design an artifact in the form of a framework-aware static security scanner for multi-framework PHP applications to improve the relevance of vulnerability detection through a combination of general and framework-specific rules. The study employs the Design Science Research approach, covering problem identification, objective definition, artifact design and development, demonstration, and evaluation. The resulting artifact, VANGUARD, is implemented in Go and integrates framework context detection, rule-based source-code scanning, OSV-based dependency vulnerability checking, scan history, comparison with previous scans, and reporting in TUI, JSON, SARIF, HTML, and Markdown formats. The current implementation covers 464 security rules across 152 YAML files, including 98 general rules and 366 framework-specific rules. Evaluation was conducted in three layers: internal functional validation, workspace-level scanning of the research repository, and controlled PHP fixture testing covering 12 vulnerable scenarios and 12 safe scenarios. The results show that 97 internal test cases passed, all 12 planted vulnerability scenarios across the positive fixtures were detected, all 12 safe scenarios produced no findings, precision, recall, specificity, accuracy, and F1-score on the controlled dataset each reached 100%, the average scan duration for positive fixtures was 32.8322 ms, and the comparison between a recognized Laravel fixture and a metadata-stripped clone yielded 6 findings versus 0 findings. In addition, scanning the workspace root produced 12 findings, all of which originated from the `research_fixtures` directory, indicating that the current artifact works best when a scan target represents a single dominant project context. The main contribution of this study lies in proposing a lightweight, structured framework-aware static security scanning model that has demonstrated a measurable detection effect in the initial evaluation. This study is expected to enrich application security research in the Information Systems domain while also providing a practical artifact for auditing modern PHP applications.

**Keywords:** web application security, PHP, static application security testing, multi-framework, source code analysis, DevSecOps

## 1. Pendahuluan

Keamanan aplikasi web merupakan salah satu persoalan inti dalam pengembangan sistem informasi modern. Organisasi saat ini bergantung pada aplikasi web untuk menjalankan proses bisnis, pelayanan publik, pertukaran data, dan transaksi digital. Ketergantungan tersebut menjadikan kerentanan aplikasi web sebagai risiko yang berdampak langsung terhadap proses organisasi. Celah pada level source code, konfigurasi, maupun komponen pihak ketiga dapat menimbulkan pencurian data, eskalasi hak akses, gangguan layanan, hingga *remote code execution*. Oleh karena itu, penguatan keamanan tidak dapat hanya dilakukan pada tahap implementasi akhir, melainkan perlu dimulai sejak tahap pengembangan kode.

Urgensi pengamanan sejak awal semakin kuat jika dikaitkan dengan karakteristik risiko aplikasi web saat ini. Secara umum, OWASP Top 10:2025 menjadi rujukan publik terbaru mengenai risiko keamanan aplikasi web [1]. Namun demikian, implementasi rule dalam artefak VANGUARD saat penelitian ini masih dominan mengikuti pemetaan OWASP Top 10:2021 karena basis aturan telah lebih dahulu disusun dengan acuan tersebut [8]. Kondisi ini penting dicatat agar deskripsi artefak tetap sesuai dengan keadaan implementasi yang sebenarnya. Baik pada OWASP Top 10:2021 maupun versi 2025, tema-tema seperti kontrol akses, konfigurasi, injeksi, dependensi, dan integritas perangkat lunak tetap menempati posisi sentral dalam risiko aplikasi web. Hal tersebut menunjukkan bahwa kelemahan keamanan tidak hanya muncul dari logika bisnis aplikasi, tetapi juga dari konfigurasi yang tidak tepat, penggunaan dependensi yang rentan, serta praktik implementasi yang tidak aman. Dengan demikian, dibutuhkan pendekatan yang mampu membantu pengembang dan auditor mengidentifikasi kelemahan tersebut secara lebih dini.

Dalam konteks bahasa pemrograman server-side, PHP masih memiliki relevansi yang sangat tinggi. Statistik W3Techs per 10 Maret 2026 menunjukkan bahwa PHP digunakan oleh 71,9% situs web yang diketahui menggunakan bahasa pemrograman sisi server [2]. Dominasi tersebut menjadikan PHP tetap penting dalam kajian keamanan aplikasi. Namun, ekosistem PHP modern tidak lagi bersifat homogen. Aplikasi PHP saat ini berkembang dalam berbagai framework dan *content management system* seperti Laravel, Symfony, WordPress, CodeIgniter, Yii2, dan CakePHP. Masing-masing memiliki struktur direktori, file konfigurasi, pola interaksi data, dan potensi kerentanan yang berbeda. Kondisi ini menyebabkan pendekatan keamanan yang terlalu generik sering kali kurang memadai.

Salah satu pendekatan yang umum digunakan untuk mendeteksi kelemahan sejak awal pengembangan adalah *static application security testing* (SAST). Metode ini memiliki keunggulan karena dapat memeriksa source code tanpa mengeksekusi program, sehingga cocok untuk proses audit awal, *pre-commit checking*, dan integrasi CI/CD. Namun, efektivitas alat SAST sangat dipengaruhi oleh kemampuan alat dalam memahami konteks sistem yang diperiksa. Pada aplikasi berbasis framework, perilaku aplikasi tidak hanya ditentukan oleh source code inti, tetapi juga oleh abstraksi framework, berkas konfigurasi, dan pola struktur proyek. Tanpa pemahaman tersebut, alat analisis statis berpotensi menghasilkan *false positive* yang tinggi atau mengabaikan kerentanan yang bersifat spesifik terhadap framework tertentu.

Penelitian terdahulu menunjukkan bahwa aplikasi berbasis framework memang menghadirkan tantangan tersendiri bagi analisis statis. Sridharan dkk. menunjukkan bahwa *static taint analysis* menjadi kurang efektif ketika alat tidak memahami perilaku framework dan konfigurasi aplikasi [3]. Penelitian Agrawal dkk. juga menegaskan pentingnya analisis source code dalam meningkatkan keamanan aplikasi web, tetapi kerangka yang ditawarkan masih bersifat umum [4]. Di sisi lain, Zhao dkk. menunjukkan bahwa evaluasi alat PHP SAST masih menghadapi kelemahan metodologis karena belum adanya kriteria yang cukup sistematis untuk membandingkan kemampuan alat secara andal [5]. Ketiga studi tersebut menunjukkan adanya kebutuhan untuk menghadirkan artefak yang bukan hanya diuji, tetapi juga dirancang secara eksplisit agar mampu bekerja secara kontekstual pada aplikasi PHP modern.

Berdasarkan kondisi tersebut, penelitian ini memfokuskan diri pada perancangan artefak bernama VANGUARD, yaitu *framework-aware static security scanner* untuk aplikasi PHP multi-framework. Artefak ini dirancang untuk mendeteksi konteks framework secara otomatis, memuat rule keamanan umum dan rule spesifik framework, memadukan analisis source code dan pemeriksaan dependensi berbasis OSV [6], menyimpan histori scan, serta menghasilkan laporan yang dapat digunakan untuk kebutuhan audit teknis maupun diarahkan ke pipeline DevSecOps. Fokus penelitian ini bukan membangun *deep program analysis engine* seperti *symbolic execution*, melainkan menghasilkan model pemindaian yang ringan, terstruktur, dan operasional.

Rumusan masalah penelitian ini adalah sebagai berikut. Pertama, bagaimana merancang alat analisis keamanan statis yang mampu mengenali konteks framework pada aplikasi PHP secara otomatis. Kedua, bagaimana mengembangkan basis aturan keamanan yang memadukan rule umum dan rule spesifik framework berdasarkan OWASP, CWE, dan CVSS. Ketiga, bagaimana mengintegrasikan pemindaian source code, konfigurasi, dan dependensi ke dalam satu artefak yang operasional. Keempat, bagaimana mendeskripsikan kondisi artefak saat ini secara objektif dan menyusun rancangan evaluasi yang mampu menilai efektivitas serta efisiensinya.

Tujuan penelitian ini adalah merancang dan mendeskripsikan artefak VANGUARD sebagai alat *framework-aware static security scanning* untuk aplikasi PHP multi-framework. Secara rinci, tujuan tersebut mencakup: (1) merancang mekanisme deteksi konteks proyek dan framework, (2) menyusun basis aturan keamanan yang relevan dengan OWASP, CWE, dan CVSS, (3) mengintegrasikan pemindaian source code dan dependensi, (4) mendokumentasikan kondisi implementasi artefak saat penelitian, dan (5) menyusun rancangan evaluasi awal untuk pengujian lebih lanjut.

Penelitian ini dibatasi pada target aplikasi berbasis PHP dan tidak mencakup *dynamic analysis*, verifikasi eksploit, *symbolic execution*, atau jaminan bahwa seluruh kerentanan dapat dideteksi. Pendekatan deteksi dalam artefak berfokus pada rule berbasis *regex*, *contains*, *entropy*, deteksi berkas, dan pemeriksaan konfigurasi. Selain itu, dukungan pemeriksaan dependensi saat ini terbatas pada ekosistem Packagist dan npm, sesuai dengan mekanisme pembacaan *lockfile* yang telah diimplementasikan.

Kontribusi penelitian ini dapat diringkas dalam empat poin. Pertama, penelitian ini menawarkan model artefak *framework-aware static security scanning* yang memadukan deteksi konteks framework dan pemuatan rule yang relevan. Kedua, penelitian ini menyusun basis aturan yang terdokumentasi dan dapat ditelusuri ke kategori severity, CWE, OWASP, dan CVSS. Ketiga, penelitian ini mengintegrasikan analisis source code dan pemeriksaan dependensi dalam satu alur kerja. Keempat, penelitian ini mendokumentasikan kondisi artefak secara objektif sehingga evaluasi lanjutan dapat dilakukan di atas dasar implementasi yang benar-benar ada, bukan asumsi konseptual.

## 2. Tinjauan Pustaka dan Gap Penelitian

### 2.1 Keamanan aplikasi web dan static analysis

Static analysis merupakan teknik analisis perangkat lunak tanpa mengeksekusi program secara langsung. Dalam konteks keamanan aplikasi, teknik ini digunakan untuk mengidentifikasi pola kelemahan pada source code, konfigurasi, dan artefak pendukung. Kelebihan static analysis terletak pada kemampuannya mendeteksi kelemahan lebih awal, sehingga biaya perbaikan dapat ditekan dan integrasi ke proses pengembangan dapat dilakukan lebih cepat. Dalam lingkungan pengembangan modern, pendekatan ini relevan dengan prinsip *shift-left security* dan DevSecOps karena dapat ditempatkan pada fase *pre-commit*, *pull request*, maupun pipeline CI/CD.

Namun demikian, efektivitas static analysis tidak sepenuhnya ditentukan oleh jumlah rule yang dimiliki suatu alat. Ketepatan deteksi juga ditentukan oleh seberapa baik alat memahami karakteristik sistem yang sedang dianalisis. Pada aplikasi berbasis framework, file konfigurasi, pola pemanggilan layanan, *middleware*, *template engine*, dan konvensi struktur direktori dapat memengaruhi bentuk serta lokasi kerentanan. Oleh karena itu, static analysis yang tidak mempertimbangkan konteks framework cenderung memiliki keterbatasan dalam hal presisi dan relevansi.

### 2.2 Static analysis pada aplikasi berbasis framework

Sridharan dkk. melalui penelitian F4F menunjukkan bahwa aplikasi berbasis framework menimbulkan tantangan serius bagi static analysis, karena perilaku penting aplikasi tersebar di dalam abstraksi framework dan konfigurasi [3]. Penelitian tersebut mengusulkan cara untuk menyusun spesifikasi perilaku framework agar analisis lebih efektif. Temuan ini menegaskan bahwa framework bukan sekadar lapisan tambahan, tetapi bagian inti dari objek analisis. Meskipun demikian, pendekatan tersebut lebih dekat dengan *program analysis* yang kompleks dan belum berorientasi pada artefak ringan yang mudah dioperasikan untuk kebutuhan praktis organisasi.

Pada sisi lain, Agrawal dkk. menekankan bahwa analisis source code dapat digunakan sebagai dasar penguatan keamanan aplikasi web [4]. Penelitian ini penting karena mengonfirmasi bahwa pendekatan berbasis kode tetap relevan untuk mendukung pengendalian keamanan. Akan tetapi, pendekatan yang diusulkan masih bersifat umum dan belum membedakan kebutuhan keamanan antar-framework secara eksplisit. Dalam konteks PHP multi-framework, kebutuhan tersebut justru menjadi krusial.

### 2.3 Evaluasi alat PHP SAST

Penelitian Zhao dkk. menunjukkan bahwa benchmark alat PHP SAST masih terbatas dan evaluasi terhadap alat-alat tersebut belum cukup sistematis [5]. Salah satu inti temuan penelitian tersebut adalah adanya kesulitan untuk mengukur kemampuan deteksi alat secara andal ketika kompleksitas dan ketidakpastian kasus uji tidak dikendalikan secara baik. Temuan ini penting karena menunjukkan bahwa permasalahan penelitian pada domain PHP SAST bukan hanya terkait algoritma deteksi, melainkan juga menyangkut metodologi evaluasi dan desain artefak yang diuji.

### 2.4 Open-source vulnerability intelligence

Selain source code, komponen dependensi juga menjadi sumber risiko keamanan yang signifikan. Dalam basis rule artefak saat ini, isu komponen rentan dan usang masih dipetakan mengikuti OWASP Top 10:2021 [8]. Untuk itu, pemeriksaan terhadap dependensi perlu menjadi bagian dari arsitektur pemindaian keamanan. OSV menyediakan basis data dan API kerentanan open-source yang dapat digunakan untuk memetakan package dan versinya terhadap kerentanan yang diketahui [6]. Integrasi basis data seperti OSV ke dalam artefak analisis keamanan berpotensi meningkatkan cakupan deteksi pada level *software composition*.

### 2.5 Gap penelitian

Berdasarkan kajian pustaka, terdapat beberapa gap utama yang menjadi dasar penelitian ini. Pertama, penelitian terdahulu telah menunjukkan pentingnya konteks framework dalam analisis keamanan, tetapi belum banyak menghasilkan artefak ringan yang secara eksplisit ditujukan untuk aplikasi PHP multi-framework. Kedua, pendekatan analisis source code yang ada cenderung bersifat umum sehingga belum memadai untuk kebutuhan rule keamanan yang spesifik terhadap framework. Ketiga, penelitian mutakhir lebih banyak menyoroti benchmark dan evaluasi alat PHP SAST daripada merancang artefak baru yang siap digunakan dalam skenario DevSecOps. Keempat, masih terbatas penelitian yang memadukan deteksi konteks framework, rule keamanan, pemeriksaan dependensi, histori scan, dan keluaran yang siap diintegrasikan dalam satu artefak yang operasional.

Tabel 1 merangkum state of the art dan gap penelitian yang menjadi landasan pengembangan artefak ini.

| Studi | Fokus | Keterbatasan | Peluang yang Diisi Penelitian Ini |
|---|---|---|---|
| Sridharan dkk. [3] | Analisis taint pada aplikasi berbasis framework | Berorientasi pada analisis program yang kompleks, belum pada artefak ringan dan operasional | Menyusun artefak ringan yang tetap memperhatikan konteks framework |
| Agrawal dkk. [4] | Kerangka analisis source code untuk keamanan aplikasi web | Masih umum, belum fokus pada PHP multi-framework | Menurunkan rule umum dan rule spesifik framework untuk PHP |
| Zhao dkk. [5] | Benchmark dan evaluasi alat PHP SAST | Menekankan evaluasi, bukan perancangan artefak baru | Merancang artefak baru sekaligus menyiapkan protokol evaluasi |
| OSV [6] | Basis data kerentanan komponen open-source | Tidak menyediakan model pemindaian source code secara langsung | Mengintegrasikan pemeriksaan dependensi ke dalam alat framework-aware |

Dengan demikian, gap utama penelitian ini adalah belum tersedianya model *framework-aware static security scanning* yang ringan, terstruktur, berbasis standar keamanan, dan sesuai dengan kondisi operasional pengembangan aplikasi PHP multi-framework. Penelitian ini berupaya mengisi gap tersebut melalui perancangan artefak VANGUARD.

## 3. Metode Penelitian

Penelitian ini menggunakan pendekatan *Design Science Research* (DSR) karena berorientasi pada pembangunan artefak untuk menyelesaikan masalah praktis secara sistematis [7]. Dalam penelitian Sistem Informasi, DSR relevan ketika kontribusi utama terletak pada artefak yang dapat diimplementasikan, diuji, dan dievaluasi. Pada penelitian ini, artefak yang dikembangkan adalah VANGUARD, yaitu alat *framework-aware static security scanning* untuk aplikasi PHP multi-framework.

### 3.1 Desain penelitian

Desain penelitian mengikuti logika DSR yang terdiri atas identifikasi masalah, perumusan tujuan, desain-pengembangan artefak, demonstrasi, evaluasi, dan komunikasi hasil. Dalam konteks penelitian ini, alur tersebut diterapkan sebagai berikut.

1. **Identifikasi masalah.** Tahap ini menelaah keterbatasan pendekatan SAST generik pada aplikasi PHP multi-framework dan mengidentifikasi perlunya pemindaian yang memahami konteks framework.
2. **Perumusan tujuan solusi.** Tahap ini menetapkan kebutuhan artefak, yaitu kemampuan mengenali framework, memuat rule yang relevan, memeriksa dependensi, dan menghasilkan keluaran yang dapat digunakan dalam audit teknis.
3. **Desain dan pengembangan artefak.** Tahap ini meliputi perancangan arsitektur, mekanisme akuisisi source, resolver konteks, mesin rule scanning, dependency scanner, model data temuan, dan reporter.
4. **Demonstrasi.** Tahap ini memastikan artefak dapat dijalankan pada target scan aktual.
5. **Evaluasi.** Tahap ini dilakukan melalui dua lapis pengujian, yaitu validasi fungsional internal dan uji coba pada fixture PHP terkontrol.

### 3.2 Objek, unit analisis, dan sumber data

Objek penelitian ini adalah project perangkat lunak VANGUARD yang berada pada workspace penelitian. Unit analisis penelitian mencakup:

1. struktur artefak perangkat lunak,
2. basis aturan keamanan,
3. perilaku deteksi pada skenario kerentanan yang dikendalikan,
4. hasil pengujian internal project.

Sumber data penelitian dibagi menjadi dua kelompok. Pertama, data konseptual berupa literatur, standar keamanan, CWE, CVSS, dan OSV sebagai dasar penyusunan kebutuhan artefak. Kedua, data implementasi berupa source code VANGUARD, 464 rule keamanan pada 152 berkas YAML, hasil *unit test*, hasil *code coverage*, dan keluaran scan dalam format JSON.

### 3.3 Prosedur perancangan artefak

Perancangan artefak dilakukan secara bertahap. Pertama, source target diperoleh melalui *provider* dari direktori lokal atau URL Git. Kedua, *resolver* mendeteksi konteks proyek dengan membaca `composer.json`, `package.json`, struktur direktori, file khas framework, serta `.env`. Ketiga, *orchestrator* memuat rule umum dan rule spesifik framework sesuai hasil resolusi konteks. Keempat, *rules scanner* memeriksa source code dan konfigurasi menggunakan pendekatan *regex*, *contains*, *entropy*, *file existence*, dan *project scope pattern*. Kelima, *dependency scanner* memeriksa package pada *lockfile* melalui OSV. Keenam, hasil akhir disimpan dan dilaporkan dalam format TUI, JSON, SARIF, HTML, dan Markdown.

### 3.4 Desain evaluasi

Evaluasi dalam penelitian ini disusun agar tidak berhenti pada deskripsi fitur. Oleh karena itu, evaluasi dibagi menjadi tiga lapis agar setiap klaim pada naskah memiliki dasar bukti yang berbeda, yaitu bukti kesiapan internal, bukti perilaku pada skenario terkontrol, dan bukti penerapan pada *workspace* penelitian yang aktual.

1. **Validasi fungsional internal.** Validasi ini dilakukan dengan menjalankan seluruh test suite menggunakan `go test ./... -cover`. Tujuannya adalah memastikan komponen inti artefak telah berjalan sesuai perilaku yang diharapkan oleh pengembang, sekaligus melihat distribusi cakupan pengujian pada paket inti.
2. **Uji *workspace scan* aktual.** Evaluasi ini dilakukan dengan menjalankan `go run . scan . --output json` pada root repositori penelitian. Tujuannya bukan untuk mengukur efektivitas deteksi pada domain PHP, melainkan untuk memverifikasi bahwa artefak benar-benar dapat dijalankan pada kondisi repositori terkini dan untuk mengamati perilakunya ketika target scan berisi campuran source engine Go dan fixture evaluasi PHP.
3. **Uji coba berbasis fixture terkontrol.** Evaluasi ini dilakukan dengan membuat fixture PHP yang mewakili skenario kerentanan pada tiga konteks utama: PHP generik, Laravel, dan WordPress. Selain itu dibuat satu fixture pembanding berupa salinan kode Laravel tanpa metadata framework untuk mengamati pengaruh mekanisme *framework-aware*.

### 3.5 Fixture evaluasi dan desain skenario uji

Tujuh fixture yang digunakan pada evaluasi ditunjukkan pada Tabel 2.

| Fixture | Tujuan | Konteks |
|---|---|---|
| `php_generic_control` | Menguji rule umum pada PHP generik | PHP generik |
| `laravel_framework` | Menguji rule umum dan rule spesifik Laravel | Laravel |
| `laravel_generic_clone` | Menguji efek hilangnya konteks framework pada kode Laravel-like | PHP generik pembanding |
| `wordpress_plugin` | Menguji rule spesifik WordPress plugin | WordPress |
| `php_generic_safe` | Negative control untuk PHP generik | PHP generik aman |
| `laravel_framework_safe` | Negative control untuk Laravel | Laravel aman |
| `wordpress_plugin_safe` | Negative control untuk WordPress plugin | WordPress aman |

Skenario kerentanan yang ditanam secara terkontrol pada fixture positif terdiri atas 12 skenario, yaitu 3 skenario pada `php_generic_control`, 5 skenario pada `laravel_framework`, dan 4 skenario pada `wordpress_plugin`. Sebagai pembanding negatif, disusun pula 12 skenario aman yang didistribusikan secara sepadan pada `php_generic_safe`, `laravel_framework_safe`, dan `wordpress_plugin_safe`. Fixture `laravel_generic_clone` tidak diperlakukan sebagai fixture positif maupun negatif, melainkan sebagai fixture *ablation/comparison* untuk menilai efek pengenalan framework terhadap hasil deteksi.

Pemilihan skenario dilakukan secara purposif dengan tiga pertimbangan. Pertama, skenario harus mewakili pola kerentanan yang memang menjadi target rule pada basis artefak saat ini. Kedua, skenario harus ditempatkan pada bentuk file yang lazim untuk setiap ekosistem, misalnya `.env`, `app/Models`, `app/Http/Controllers`, `config/` pada Laravel, serta file plugin tunggal pada WordPress. Ketiga, skenario dipilih agar mencakup kombinasi kelemahan konfigurasi, kelemahan logika bisnis, injeksi, dan deserialisasi, sehingga evaluasi tidak hanya bertumpu pada satu kategori rule.

### 3.6 Instrumen, perintah eksekusi, dan artefak bukti

Instrumen evaluasi pada penelitian ini terdiri atas: (1) source code VANGUARD, (2) basis rule dalam direktori `rules/`, (3) fixture evaluasi pada direktori `research_fixtures/`, dan (4) hasil scan JSON yang disimpan pada `research_results/`. Seluruh pengujian dijalankan dari root project menggunakan perintah terminal agar dapat direplikasi secara langsung pada lingkungan yang sama.

Perintah utama yang digunakan adalah `go test ./...`, `go test ./... -cover`, `go run . scan . --output json`, serta `go run . scan <path_fixture> --output json` untuk setiap fixture. Dengan desain ini, bukti evaluasi tidak hanya berupa narasi penulis, tetapi juga terikat pada artefak hasil yang dapat diaudit kembali, seperti `research_results/php_generic_control.json`, `research_results/laravel_framework.json`, `research_results/laravel_generic_clone.json`, `research_results/wordpress_plugin.json`, `research_results/php_generic_safe.json`, `research_results/laravel_framework_safe.json`, `research_results/wordpress_plugin_safe.json`, dan `research_results/self_scan_workspace.json`.

### 3.7 Metrik evaluasi

Karena satu skenario kerentanan dapat memicu lebih dari satu rule, evaluasi awal penelitian ini tidak menggunakan jumlah finding sebagai satu-satunya indikator efektivitas. Metrik yang digunakan adalah:

1. **Status lulus pengujian internal,** yaitu lulus atau gagal pada `go test ./...`.
2. **Code coverage per paket inti,** untuk melihat area yang telah mendapat pengujian lebih baik.
3. **Tingkat deteksi skenario,** dihitung dengan Persamaan (1).

\[
\text{Tingkat Deteksi Skenario} = \frac{\text{Jumlah skenario yang terdeteksi}}{\text{Jumlah skenario yang ditanam}} \times 100\%
\]

4. **Jumlah finding aktual,** untuk melihat apakah satu skenario memicu satu atau beberapa rule.
5. **Waktu pemindaian,** berdasarkan nilai `duration` pada keluaran JSON.
6. **Presisi pada dataset terkontrol,** dihitung sebagai proporsi skenario positif yang terdeteksi terhadap seluruh skenario yang ditandai positif oleh sistem pada unit skenario.
7. **Specificity,** dihitung sebagai proporsi skenario aman yang tidak menghasilkan finding.
8. **Accuracy dan F1-score pada dataset terkontrol,** dihitung dari matriks konfusi berbasis unit skenario.
9. **Efek framework-aware,** diukur dengan membandingkan hasil scan `laravel_framework` dan `laravel_generic_clone` yang memiliki pola kode serupa tetapi konteks framework berbeda.
10. **Lokasi asal finding pada *workspace scan*,** untuk membedakan apakah temuan berasal dari source engine VANGUARD atau dari fixture evaluasi yang memang sengaja rentan.

Metrik presisi, specificity, accuracy, dan F1 pada artikel ini dihitung pada level skenario terhadap dataset fixture terkontrol yang sengaja dibangun untuk penelitian. Oleh karena itu, nilai yang dihasilkan harus dibaca sebagai *observed performance under controlled test conditions*, bukan sebagai estimasi final performa pada seluruh populasi proyek PHP produksi.

Rumus yang digunakan ditunjukkan pada Persamaan (2) sampai Persamaan (5).

\[
\text{Precision} = \frac{TP}{TP + FP} \times 100\%
\]

\[
\text{Specificity} = \frac{TN}{TN + FP} \times 100\%
\]

\[
\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN} \times 100\%
\]

\[
\text{F1-score} = \frac{2TP}{2TP + FP + FN} \times 100\%
\]

### 3.8 Prosedur pengumpulan dan analisis data

Prosedur evaluasi dilakukan melalui langkah berikut.

1. Menjalankan `go test ./... -cover` pada project VANGUARD.
2. Menghitung jumlah test case internal dari seluruh berkas `*_test.go`.
3. Menjalankan `go run . scan . --output json` untuk memperoleh bukti penerapan artefak pada *workspace* penelitian yang aktual.
4. Membuat fixture PHP terkontrol yang memuat skenario kerentanan yang telah ditentukan.
5. Menyusun negative control yang merepresentasikan implementasi aman untuk kategori skenario yang sama.
6. Menjalankan perintah `go run . scan <path_fixture> --output json` untuk setiap fixture positif, fixture aman, dan fixture pembanding.
7. Menyimpan hasil scan JSON sebagai data evaluasi.
8. Memetakan ID finding yang muncul ke skenario kerentanan yang sengaja ditanam.
9. Menentukan TP, FN, FP, dan TN pada unit skenario dengan membandingkan hasil scan terhadap label fixture positif dan fixture aman.
10. Mengelompokkan finding berdasarkan severity, file, dan asal direktori untuk membedakan temuan dari fixture dengan temuan dari source engine.
11. Menganalisis tingkat deteksi skenario, presisi, specificity, accuracy, F1-score, waktu pemindaian, jumlah finding, dan efek konteks framework.

Dengan prosedur ini, evaluasi dalam penelitian tidak hanya menyatakan bahwa artefak "berjalan", tetapi juga menunjukkan bagaimana artefak merespons skenario keamanan yang relevan dengan domain penggunaannya.

### 3.9 Ancaman terhadap validitas

Beberapa ancaman terhadap validitas dicatat sejak awal. Pertama, fixture evaluasi disusun oleh peneliti, sehingga tetap ada risiko *author bias* dalam memilih pola yang relatif dekat dengan rule yang tersedia. Risiko ini dikurangi dengan menggunakan skenario yang tersebar pada beberapa kategori dan beberapa lapisan file, bukan hanya satu pola sintaksis. Kedua, jumlah fixture masih terbatas, sehingga hasil tidak dapat digeneralisasi ke seluruh populasi aplikasi PHP produksi. Ketiga, *workspace scan* pada root repositori mengandung source engine Go dan fixture PHP yang sengaja rentan, sehingga hasilnya diperlakukan sebagai *runtime smoke test* dan observasi perilaku *mixed workspace*, bukan sebagai ukuran utama efektivitas. Keempat, belum adanya korpus negatif berlabel menyebabkan artikel ini belum dapat menyajikan *precision* dan *false positive rate* formal. Pernyataan keterbatasan ini penting agar ruang lingkup kesimpulan tetap proporsional dengan bukti yang tersedia.

### 3.10 Replikasi pengujian

Agar proses pengujian mudah direplikasi, rangkaian perintah inti yang digunakan pada penelitian ini ditunjukkan pada Kode 1.

```powershell
go test ./...
go test ./... -cover

go run . scan . --output json

go run . scan research_fixtures\php_generic_control --output json
go run . scan research_fixtures\laravel_framework --output json
go run . scan research_fixtures\laravel_generic_clone --output json
go run . scan research_fixtures\wordpress_plugin --output json
go run . scan research_fixtures\php_generic_safe --output json
go run . scan research_fixtures\laravel_framework_safe --output json
go run . scan research_fixtures\wordpress_plugin_safe --output json
```

Hasil dari pengujian tersebut kemudian disimpan sebagai artefak bukti dalam format JSON. Dengan demikian, proses pengujian pada artikel ini dapat ditelusuri ulang tidak hanya dari penjelasan naratif, tetapi juga dari file bukti yang bersesuaian pada direktori `research_results/`.

## 4. Kondisi Artefak, Hasil Perancangan, dan Pengujian

### 4.1 Kondisi project saat penelitian

Penelitian ini tidak berhenti pada perumusan konsep, tetapi berangkat dari artefak yang sudah diimplementasikan. Oleh karena itu, penting untuk mendokumentasikan kondisi project saat penelitian agar naskah tidak melebih-lebihkan kapabilitas sistem. Tabel 3 merangkum kondisi implementasi VANGUARD saat artikel ini disusun.

| Aspek | Kondisi saat penelitian |
|---|---|
| Bahasa implementasi | Go 1.24.2 |
| Bentuk aplikasi | CLI dengan mode TUI dan mode headless |
| Perintah utama | `scan`, `init`, `ci github` |
| Akuisisi source | Direktori lokal dan URL Git |
| Resolusi konteks | `composer.json`, `package.json`, struktur direktori, file khas framework, `.env` |
| Framework-aware rule pack | Laravel, Symfony, WordPress, CodeIgniter, CodeIgniter 4, Yii2, CakePHP |
| Baseline rule | `common` |
| Pemeriksaan dependensi | Packagist dan npm melalui `composer.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Format keluaran | TUI, JSON, SARIF, HTML, Markdown |
| Histori scan | Tersedia, termasuk perbandingan dengan scan sebelumnya |
| Generator workflow | Tersedia untuk GitHub Actions, namun template belum divalidasi penuh dan masih memerlukan penyesuaian flag CLI |
| Validasi internal | `go test ./...` lulus seluruhnya |
| Verifikasi runtime | `go run . scan . --output json` berhasil dijalankan |

Temuan penting dari inspeksi kondisi artefak adalah bahwa resolver framework saat ini mampu mengenali beberapa ekosistem tambahan seperti Slim, Laminas, Phalcon, Drupal, Joomla, Magento, serta sebagian framework JavaScript seperti Next.js, Express, Angular, React, dan Vue. Namun, *framework-specific rule pack* yang saat ini benar-benar tersedia baru mencakup tujuh kelompok utama pada ekosistem PHP, yaitu Laravel, Symfony, WordPress, CodeIgniter, CodeIgniter 4, Yii2, dan CakePHP. Dengan demikian, klaim *framework-aware* dalam penelitian ini dibatasi pada framework yang benar-benar memiliki basis aturan spesifik.

### 4.2 Arsitektur artefak

Arsitektur VANGUARD terdiri atas beberapa komponen utama. Komponen pertama adalah *provider* yang bertanggung jawab memperoleh source code dari direktori lokal atau melakukan kloning dari URL Git. Komponen kedua adalah *resolver* yang memetakan konteks proyek melalui file seperti `composer.json`, `package.json`, struktur direktori, file konfigurasi, dan `.env`. Komponen ketiga adalah *orchestrator* yang mengatur alur kerja pemindaian, pemuatan rule, eksekusi scanner, pasca-proses, dan pembentukan laporan.

Komponen keempat adalah *rules scanner*, yaitu mesin pemindaian source code berbasis aturan yang bekerja menggunakan *regex*, *contains*, *entropy*, dan pemeriksaan file/proyek. Mesin ini juga memanfaatkan praproses seperti penghapusan komentar dan pemindaian paralel untuk menjaga efisiensi. Komponen kelima adalah *dependency scanner* yang memanfaatkan data dari OSV untuk menilai apakah dependensi yang ditemukan berada pada versi yang diketahui rentan. Komponen keenam adalah *reporter* yang menghasilkan keluaran dalam berbagai format untuk kebutuhan manusia maupun integrasi alat.

### 4.3 Basis aturan dan cakupan deteksi

Implementasi saat ini mencakup 464 rule keamanan pada 152 berkas YAML. Rule-rule tersebut terbagi ke dalam kategori umum dan kategori spesifik framework. Distribusi rule aktual ditunjukkan pada Tabel 4.

| Kategori rule | Jumlah rule |
|---|---:|
| common | 98 |
| laravel | 66 |
| symfony | 52 |
| wordpress | 51 |
| codeigniter | 49 |
| codeigniter4 | 50 |
| yii2 | 49 |
| cakephp | 49 |
| **Total** | **464** |

Distribusi tersebut menunjukkan bahwa artefak tidak hanya memuat rule keamanan generik, tetapi benar-benar memiliki diferensiasi rule untuk framework tertentu. Rule-rule tersebut meliputi kategori *injection*, *deserialization*, *SSRF*, *auth*, *crypto*, *debug*, *file upload*, *middleware security*, *logging and monitoring*, *session security*, *supply chain*, *API security*, dan *business logic*. Setiap rule dapat dipetakan ke severity, kategori, CWE, OWASP, referensi, *confidence*, serta skor dan vektor CVSS bila tersedia. Dengan struktur ini, hasil pemindaian tidak hanya berupa temuan mentah, tetapi juga membawa konteks keamanan yang lebih kaya.

Perlu dicatat bahwa pemetaan OWASP pada basis rule saat ini masih dominan menggunakan nomenklatur OWASP Top 10:2021, sebagaimana terlihat pada struktur rule yang ada. Karena OWASP Top 10:2025 telah dirilis [1], maka penyesuaian penuh basis aturan ke terminologi dan pengelompokan 2025 merupakan agenda pengembangan yang relevan untuk penelitian lanjutan. Pernyataan ini penting agar klaim penelitian tetap sinkron dengan kondisi artefak pada saat artikel disusun.

### 4.4 Output, histori, dan integrasi operasional

Artefak ini dirancang bukan hanya untuk mendeteksi kelemahan, tetapi juga untuk menghasilkan keluaran yang dapat ditindaklanjuti. JSON berfungsi sebagai format interoperabilitas, SARIF mendukung integrasi dengan ekosistem *code scanning*, HTML dan Markdown memudahkan pelaporan manual, sedangkan mode TUI mendukung penggunaan interaktif di terminal. Selain itu, artefak juga menyimpan histori scan dan membandingkan temuan saat ini dengan scan sebelumnya untuk mengidentifikasi temuan baru maupun temuan yang telah terselesaikan. Fitur ini penting dari sudut pandang manajemen keamanan karena memungkinkan perubahan kondisi keamanan proyek dilihat dari waktu ke waktu.

### 4.5 Verifikasi kondisi aktual artefak

Untuk memastikan bahwa artikel ini benar-benar sesuai dengan kondisi project terkini, dilakukan verifikasi ulang terhadap repositori VANGUARD setelah seluruh fixture evaluasi disimpan di dalam *workspace* penelitian. Pertama, *unit test* dijalankan menggunakan `go test ./...` dan seluruh paket pengujian berhasil lulus. Kedua, artefak dijalankan menggunakan perintah `go run . scan . --output json` pada root repositori. Hasilnya menunjukkan bahwa proses pemindaian berjalan sukses, dua scanner aktif dijalankan (*dependency-scanner* dan *rules-scanner*), durasi pemindaian yang tercatat pada laporan JSON adalah `110.5917ms`, dan jumlah temuan yang dihasilkan adalah 12, yang terdiri atas 5 critical, 6 high, dan 1 medium.

Audit terhadap file hasil `research_results/self_scan_workspace.json` memperlihatkan bahwa seluruh 12 finding tersebut tidak berasal dari source engine Go VANGUARD, melainkan seluruhnya berasal dari dua direktori fixture yang memang sengaja berisi skenario rentan, yaitu `research_fixtures/wordpress_plugin` dan `research_fixtures/php_generic_control`. Pada scan root ini, resolver memuat 98 rule umum dan 51 rule WordPress, sehingga tidak ada finding Laravel-spesifik yang muncul meskipun fixture Laravel juga berada di dalam *workspace*. Berdasarkan observasi tersebut, dapat diinferensikan bahwa perilaku resolver saat ini mengasumsikan satu konteks proyek dominan untuk setiap target scan. Konsekuensinya, scan pada root *workspace* heterogen lebih tepat diposisikan sebagai uji runtime dan observasi perilaku konteks campuran, bukan sebagai ukuran utama efektivitas deteksi artefak.

### 4.6 Pengujian fungsional internal

Validasi fungsional internal dilakukan untuk melihat tingkat kesiapan komponen inti artefak. Berdasarkan perhitungan pada seluruh berkas `*_test.go`, VANGUARD saat ini memiliki 97 test case internal. Ketika dijalankan dengan `go test ./... -cover`, seluruh paket pengujian lulus. Ringkasan cakupan pengujian paket inti disajikan pada Tabel 5.

| Paket | Coverage |
|---|---:|
| `internal/reporter` | 71.3% |
| `internal/scanner` | 67.9% |
| `internal/models` | 57.6% |
| `internal/resolver` | 54.5% |
| `internal/eventbus` | 50.0% |
| `internal/provider` | 35.4% |
| `internal/config` | 33.1% |
| `internal/orchestrator` | 19.2% |
| `internal/store` | 14.6% |

Hasil tersebut menunjukkan bahwa pengujian paling kuat terkonsentrasi pada komponen inti deteksi, yaitu `scanner`, `reporter`, `resolver`, dan `models`. Area dengan cakupan lebih rendah berada pada `orchestrator` dan `store`, sedangkan paket CLI/TUI belum memiliki pengujian yang berarti. Bagi naskah penelitian, temuan ini penting karena menunjukkan bahwa artefak sudah memiliki dasar validasi teknis yang cukup baik pada mesin pemindaian, tetapi belum merata pada seluruh lapisan aplikasi.

### 4.7 Pengujian efektivitas dan presisi pada fixture PHP terkontrol

Setelah validasi internal, dilakukan uji coba pada fixture PHP terkontrol untuk melihat efektivitas artefak terhadap skenario kerentanan yang relevan dengan domain target VANGUARD. Hasil ringkas pengujian ditunjukkan pada Tabel 6.

| Fixture | Konteks | Skenario ditanam | Finding aktual | Tingkat deteksi skenario | Durasi |
|---|---|---:|---:|---:|---:|
| `php_generic_control` | PHP generik | 3 | 5 | 100% | 25.6303 ms |
| `laravel_framework` | Laravel | 5 | 6 | 100% | 43.1715 ms |
| `wordpress_plugin` | WordPress | 4 | 6 | 100% | 29.6949 ms |

Pada tiga fixture positif tersebut, seluruh 12 skenario kerentanan yang ditanam berhasil terdeteksi setidaknya oleh satu rule yang relevan, sehingga tingkat deteksi skenario pada evaluasi awal ini adalah 100%. Rata-rata waktu pemindaian pada tiga fixture positif adalah 32.8322 ms. Jumlah finding aktual lebih tinggi daripada jumlah skenario yang ditanam karena beberapa skenario memicu lebih dari satu rule. Hal ini terutama terlihat pada `unserialize()` di fixture PHP generik dan pada `APP_KEY` lemah di fixture Laravel.

Untuk melengkapi pengukuran efektivitas dengan presisi, digunakan pula tiga fixture aman sebagai negative control. Hasilnya ditunjukkan pada Tabel 7.

| Fixture aman | Konteks | Skenario aman | Finding aktual | Hasil | Durasi |
|---|---|---:|---:|---|---:|
| `php_generic_safe` | PHP generik aman | 3 | 0 | Tidak ada false alert | 23.7681 ms |
| `laravel_framework_safe` | Laravel aman | 5 | 0 | Tidak ada false alert | 38.8156 ms |
| `wordpress_plugin_safe` | WordPress aman | 4 | 0 | Tidak ada false alert | 40.4489 ms |

Pada tiga fixture aman tersebut, tidak ditemukan finding sama sekali. Dengan demikian, pada dataset fixture terkontrol penelitian ini diperoleh matriks konfusi berbasis unit skenario sebagaimana ditunjukkan pada Tabel 8.

| Komponen | Nilai |
|---|---:|
| True Positive (TP) | 12 |
| False Negative (FN) | 0 |
| False Positive (FP) | 0 |
| True Negative (TN) | 12 |
| Precision | 100% |
| Recall | 100% |
| Specificity | 100% |
| Accuracy | 100% |
| F1-score | 100% |

Jika dibedah per fixture, `php_generic_control` menunjukkan bahwa VANGUARD mampu mendeteksi pola debug disclosure dan deserialisasi tidak aman pada kode PHP generik tanpa memerlukan konteks framework. Tiga skenario yang ditanam menghasilkan lima finding, dengan overlap terbesar terjadi pada sink `unserialize()` yang dipetakan sebagai kerentanan deserialisasi sekaligus injeksi. Pada `laravel_framework`, enam finding yang muncul tersebar pada empat lapisan artefak Laravel, yaitu `.env`, model Eloquent, controller, dan file konfigurasi. Sebaran ini menunjukkan bahwa rule Laravel tidak hanya memindai source code PHP, tetapi juga berkas konfigurasi yang berpengaruh pada keamanan aplikasi. Pada `wordpress_plugin`, enam finding yang dihasilkan mengungkap kombinasi masalah CSRF, kontrol akses/logika bisnis, SQL injection, dan output escaping pada satu file plugin. Hal ini relevan dengan pola implementasi plugin WordPress yang sering terpusat pada satu berkas utama.

Nilai akurasi, presisi, recall, specificity, dan F1-score di atas harus dibaca dalam konteks yang tepat. Nilai tersebut berlaku pada dataset fixture terkontrol yang secara sengaja disusun untuk menguji rule yang tersedia, bukan pada keseluruhan populasi proyek PHP dunia nyata. Meskipun demikian, penambahan negative control membuat artikel ini tidak lagi hanya menyatakan bahwa "skenario positif terdeteksi", tetapi juga menunjukkan bahwa pada kondisi uji yang disusun, artefak tidak menandai skenario aman sebagai temuan.

Rincian pemetaan skenario dan finding yang muncul disajikan pada Tabel 9.

| Fixture | Skenario yang ditanam | Finding yang muncul |
|---|---|---|
| `php_generic_control` | `unserialize($_POST['data'])` | `DESER-001`, `DESER-002`, `INJ-D01` |
| `php_generic_control` | `var_dump($object)` | `DBG-003` |
| `php_generic_control` | `phpinfo()` | `DBG-004` |
| `laravel_framework` | `APP_KEY=SomeRandomString` | `LAR-SECRETS-001`, `LAR-ENT-009` |
| `laravel_framework` | `APP_DEBUG=true` | `LAR-DEBUG-001` |
| `laravel_framework` | `protected $guarded = []` | `LAR-ENT-001` |
| `laravel_framework` | `DB::raw("...$email")` | `LAR-INJ-001` |
| `laravel_framework` | `'expiration' => null` | `LAR-ENT-006` |
| `wordpress_plugin` | `update_option($_POST['key'], $_POST['value'])` | `WP-ENT-001`, `WP-BIZ-001` |
| `wordpress_plugin` | `$wpdb->query(...$_GET['id'])` | `WP-ENT-002` |
| `wordpress_plugin` | `echo $_GET['name']` | `WP-ENT-005` |
| `wordpress_plugin` | `wp_update_post($_POST['post_data'])` tanpa nonce | `WP-ENT-004`, `WP-BIZ-001` |

### 4.8 Pengujian perbandingan framework-aware

Untuk menilai efek mekanisme *framework-aware*, dilakukan pembandingan antara `laravel_framework` dan `laravel_generic_clone`. Kedua fixture tersebut memuat pola kode Laravel-like yang serupa pada model dan controller, tetapi hanya `laravel_framework` yang memiliki metadata dan struktur yang memungkinkan resolver mengenalinya sebagai Laravel. Hasilnya ditunjukkan pada Tabel 10.

| Fixture | Konteks terdeteksi | Finding aktual | Durasi |
|---|---|---:|---:|
| `laravel_framework` | Laravel | 6 | 43.1715 ms |
| `laravel_generic_clone` | PHP generik | 0 | 21.3009 ms |

Hasil ini menunjukkan bahwa mekanisme *framework-aware* pada VANGUARD tidak hanya menambah jumlah rule yang dijalankan, tetapi juga memengaruhi relevansi hasil deteksi. Pada fixture Laravel, artefak memuat 98 rule umum dan 66 rule spesifik Laravel sehingga mampu menangkap pola `$guarded = []`, `DB::raw()` dengan interpolasi variabel, dan konfigurasi Sanctum yang tidak aman. Sebaliknya, ketika metadata framework dihilangkan, rule spesifik Laravel tidak dimuat dan tidak ada temuan yang muncul. Dalam konteks evaluasi ini, hasil tersebut bukan diposisikan sebagai kelemahan, melainkan sebagai bukti bahwa arsitektur alat memang menggunakan konteks framework sebagai mekanisme aktivasi rule.

Temuan perbandingan ini juga penting untuk membaca hasil *workspace scan* pada Subbagian 4.5. Fakta bahwa scan root *workspace* hanya memunculkan finding dari WordPress dan PHP generik, tetapi tidak dari Laravel, konsisten dengan perilaku resolver yang memilih satu konteks dominan untuk satu target scan. Dengan demikian, hasil uji perbandingan tidak hanya menjelaskan keberhasilan artefak pada skenario Laravel, tetapi juga membantu menjelaskan mengapa praktik penggunaan alat sebaiknya diarahkan pada root proyek yang spesifik, bukan pada *workspace* campuran yang memuat banyak subproyek berbeda.

### 4.9 Analisis mendalam hasil pengujian

Subbagian ini memerinci bagaimana setiap pengujian bekerja dan apa maknanya terhadap kapabilitas artefak. Pemisahan ini penting karena hasil pada artikel ini bukan hanya "jumlah finding", tetapi juga bukti bahwa rule tertentu benar-benar aktif pada konteks yang sesuai.

#### 4.9.1 Analisis pengujian pada PHP generik

Pengujian `php_generic_control` merepresentasikan baseline ketika target scan tidak memiliki metadata framework. Fixture ini berisi tiga pola sederhana tetapi berisiko tinggi, yaitu `unserialize()` terhadap input pengguna, `var_dump()`, dan `phpinfo()`. Hasil scan menghasilkan 5 finding dengan distribusi severity 3 critical, 1 high, dan 1 medium. Hal ini menunjukkan bahwa rule umum VANGUARD cukup agresif dalam menangkap kerentanan yang secara sintaksis sangat eksplisit.

Temuan paling menarik berada pada `unserialize($payload)`. Satu baris kode ini memicu tiga finding sekaligus, yaitu `DESER-001`, `DESER-002`, dan `INJ-D01`. Secara teknis, overlap tersebut dapat dijustifikasi karena sink yang sama memang berelasi dengan lebih dari satu kategori risiko: deserialisasi tidak aman, kurangnya pembatasan `allowed_classes`, dan kemungkinan injeksi objek berbahaya. Ini berarti VANGUARD sensitif terhadap konteks risiko yang bertumpuk pada satu sink, walaupun konsekuensinya jumlah finding tidak identik dengan jumlah skenario.

#### 4.9.2 Analisis pengujian pada Laravel

Pengujian `laravel_framework` dirancang untuk menilai apakah artefak tidak hanya mengenali Laravel, tetapi juga memanfaatkan konteks tersebut untuk memeriksa beberapa lapisan artefak sekaligus. Hasil scan menghasilkan 6 finding dengan distribusi 4 critical, 1 high, dan 1 medium. Temuan muncul dari `.env`, model, controller, dan file konfigurasi. Ini penting karena menunjukkan bahwa pendekatan *framework-aware* pada VANGUARD tidak berhenti pada pencarian pola di file `.php`, melainkan juga menjangkau file konfigurasi yang dalam praktik sering menjadi sumber kelemahan keamanan produksi.

Secara rinci, `APP_KEY=SomeRandomString` memicu dua finding berbeda, yaitu `LAR-SECRETS-001` dan `LAR-ENT-009`, karena baris yang sama dibaca sekaligus sebagai *hardcoded secret material* dan *weak application key*. `APP_DEBUG=true` memicu `LAR-DEBUG-001`, yang relevan dengan risiko kebocoran detail diagnostik di lingkungan produksi. Pada lapisan model, `protected $guarded = []` memicu `LAR-ENT-001`, yang sesuai dengan risiko *mass assignment*. Pada controller, penggunaan `DB::raw()` dengan interpolasi variabel memicu `LAR-INJ-001`, yang menegaskan bahwa rule Laravel mampu menangkap pola injeksi SQL yang terikat pada API framework. Sementara itu, konfigurasi Sanctum `'expiration' => null` memicu `LAR-ENT-006`, yang menunjukkan bahwa artefak juga memeriksa kelemahan konfigurasi token, bukan hanya source code bisnis.

#### 4.9.3 Analisis pengujian pada WordPress

Pengujian `wordpress_plugin` merepresentasikan pola implementasi plugin yang sering terkonsentrasi pada satu file utama. Hasil scan menghasilkan 6 finding dengan distribusi 2 critical dan 4 high. Secara substansi, hasil ini penting karena memperlihatkan bahwa VANGUARD mampu mendeteksi kombinasi masalah kontrol akses, CSRF, injeksi, dan output escaping dalam konteks WordPress yang sangat khas.

Baris `update_option($_POST['key'], $_POST['value'])` memicu `WP-ENT-001` dan `WP-BIZ-001`, yang secara logis dapat dipahami sebagai dua sudut pandang berbeda atas operasi yang sama: *privilege escalation* pada opsi sensitif dan mutasi bisnis tanpa pengecekan kapabilitas. Baris `$wpdb->query("SELECT * FROM wp_users WHERE id=" . $_GET['id'])` memicu `WP-ENT-002`, yang mengonfirmasi adanya deteksi terhadap *unprepared query* pada API WordPress. Baris `echo $_GET['name']` memicu `WP-ENT-005`, yang relevan dengan XSS reflektif. Sementara itu, `wp_update_post($_POST['post_data'])` tanpa verifikasi nonce memicu `WP-ENT-004` dan `WP-BIZ-001`, sehingga terlihat bahwa rule WordPress mampu membaca ketiadaan kontrol CSRF dan ketiadaan pemeriksaan kapabilitas secara bersamaan.

#### 4.9.4 Analisis negative control dan metrik presisi

Keberadaan `php_generic_safe`, `laravel_framework_safe`, dan `wordpress_plugin_safe` membuat evaluasi pada artikel ini tidak hanya menilai *detection power*, tetapi juga *false alert behavior* pada kondisi terkontrol. Ketiga fixture aman tersebut disusun agar mewakili implementasi yang secara semantik aman dan sekaligus mengikuti pola aman yang dikenali basis rule saat ini, misalnya penggunaan `json_decode()` alih-alih `unserialize()`, `APP_KEY` yang direferensikan dari environment, query Eloquent tanpa `DB::raw()`, `sanitize_text_field()`, `esc_html()`, serta mutasi WordPress dengan pengecekan kapabilitas dan nonce pada baris yang relevan.

Hasil scan yang menghasilkan 0 finding pada seluruh fixture aman menunjukkan bahwa, pada dataset terkontrol ini, rule VANGUARD tidak mengeluarkan *false alert*. Dari sudut metodologis, kondisi ini memungkinkan perhitungan precision, specificity, accuracy, dan F1-score pada level skenario. Karena seluruh 12 skenario positif terdeteksi dan seluruh 12 skenario aman tidak ditandai, maka diperoleh nilai 100% untuk kelima metrik tersebut. Sekali lagi, angka ini tidak boleh digeneralisasi ke populasi proyek nyata, tetapi penting karena menunjukkan bahwa pada kondisi uji yang dibangun secara seimbang antara skenario rentan dan skenario aman, artefak bekerja secara konsisten.

#### 4.9.5 Analisis pengujian pada workspace campuran

Pengujian pada root *workspace* berbeda secara tujuan dari fixture positif. Di sini artefak dijalankan pada repositori aktual yang memuat source engine Go, rule YAML, dan fixture PHP untuk penelitian. Hasil scan menghasilkan 12 finding dengan distribusi 5 critical, 6 high, dan 1 medium. Seluruh finding berasal dari `research_fixtures/php_generic_control` dan `research_fixtures/wordpress_plugin`; tidak ada finding yang berasal dari source engine Go maupun dari fixture Laravel.

Secara teknis, hasil ini penting karena menunjukkan dua hal. Pertama, runtime artefak stabil ketika dipakai pada kondisi repositori yang sesungguhnya. Kedua, resolver saat ini tampaknya memilih satu konteks dominan untuk setiap target scan, sehingga pada *workspace* heterogen rule WordPress aktif sedangkan rule Laravel tidak ikut dimuat pada scan root. Temuan ini sangat relevan untuk artikel karena memberi insight praktis dan akademik sekaligus: desain saat ini efektif untuk satu proyek per target scan, tetapi belum optimal untuk *workspace* multi-proyek.

## 5. Pembahasan

### 5.1 Interpretasi terhadap efektivitas artefak

Hasil evaluasi menunjukkan bahwa VANGUARD tidak hanya telah terimplementasi sebagai artefak, tetapi juga mampu menunjukkan perilaku deteksi yang relevan terhadap domain targetnya. Pada lapis validasi internal, 97 *test case* yang lulus memperlihatkan bahwa perilaku penting artefak telah diuji pada level *rule parsing*, *metadata compliance*, resolver framework, provider, reporter, dependency scanner, dan rules scanner. Cakupan pengujian yang relatif tinggi pada `internal/scanner`, `internal/reporter`, dan `internal/resolver` menunjukkan bahwa inti mesin pemindaian telah memperoleh perhatian pengujian yang memadai. Hal ini penting karena ketiga paket tersebut secara langsung memengaruhi akurasi temuan dan kualitas keluaran yang digunakan pengguna.

Pada lapis evaluasi eksternal, hasil scan terhadap fixture terkontrol menunjukkan bahwa VANGUARD mampu mendeteksi seluruh 12 skenario kerentanan yang sengaja ditanam pada tiga fixture positif. Capaian ini menunjukkan bahwa secara *scenario-level detection*, artefak memberikan hasil yang kuat pada evaluasi awal. Namun, artikel ini secara sadar tidak mengubah angka tersebut menjadi klaim *precision* atau *general recall*, karena belum ada korpus negatif berlabel dan belum ada benchmark produksi yang cukup besar. Dengan posisi ini, hasil 100% lebih tepat dibaca sebagai bukti bahwa rule yang diimplementasikan benar-benar aktif, dapat terpanggil pada konteks yang tepat, dan mampu memunculkan finding pada skenario yang memang mewakili domain target artefak.
Pada lapis evaluasi eksternal, hasil scan terhadap fixture terkontrol menunjukkan bahwa VANGUARD mampu mendeteksi seluruh 12 skenario kerentanan yang sengaja ditanam pada tiga fixture positif. Capaian ini menunjukkan bahwa secara *scenario-level detection*, artefak memberikan hasil yang kuat pada evaluasi awal. Berbeda dari versi evaluasi sebelumnya yang hanya menilai sisi positif, artikel ini juga menambahkan 12 skenario aman melalui tiga negative control. Karena seluruh skenario positif terdeteksi dan seluruh skenario aman tidak ditandai, maka pada dataset fixture terkontrol diperoleh precision, recall, specificity, accuracy, dan F1-score sebesar 100%. Nilai ini penting sebagai bukti *observed correctness* pada kondisi uji yang dibangun secara terkendali.

Meski demikian, angka 100% tersebut tidak boleh dipahami sebagai bukti bahwa VANGUARD telah mencapai akurasi sempurna pada seluruh aplikasi PHP nyata. Secara metodologis, angka itu hanya sah pada level skenario dalam dataset uji yang dibangun peneliti. Dengan kata lain, kontribusi artikel ini adalah menunjukkan bahwa artefak mampu membedakan skenario rentan dan skenario aman pada lingkungan uji terkontrol, bukan mengklaim bahwa seluruh kemungkinan variasi kode produksi akan diperlakukan seakurat itu.

Jumlah finding aktual yang lebih besar daripada jumlah skenario juga menunjukkan karakteristik penting dari pendekatan *rule-based*, yaitu satu pola kerentanan dapat dipandang dari lebih dari satu sudut risiko. Sebagai contoh, `unserialize($_POST['data'])` terdeteksi sebagai deserialisasi tidak aman sekaligus deserialisasi berbahaya pada konteks injeksi. Hal yang sama terjadi pada `APP_KEY` lemah di Laravel dan operasi bisnis sensitif pada WordPress. Dari sudut pandang keamanan, overlap ini meningkatkan sensitivitas deteksi. Dari sudut pandang operasional, overlap tersebut menandakan perlunya *triage*, deduplikasi, atau *finding grouping* pada pengembangan berikutnya agar pengalaman pengguna tetap efisien.

### 5.2 Relevansi pendekatan framework-aware

Hasil pembandingan `laravel_framework` dan `laravel_generic_clone` memberikan bukti yang paling langsung terhadap hipotesis desain artefak. Pada fixture yang dikenali sebagai Laravel, VANGUARD menghasilkan 6 finding yang semuanya berkaitan langsung dengan konteks framework. Pada salinan kode yang sama tetapi tanpa metadata framework, VANGUARD menghasilkan 0 finding. Temuan ini memperlihatkan dua hal. Pertama, mekanisme resolusi konteks memang berfungsi sebagai gerbang aktivasi rule. Kedua, rule spesifik framework membantu menekan potensi aktivasi rule yang tidak relevan pada proyek PHP generik. Dengan demikian, konsep *framework-aware* pada artefak ini bukan sekadar label, melainkan benar-benar memengaruhi hasil pemindaian.

Hasil ini sejalan dengan gap penelitian yang telah dipetakan pada bagian tinjauan pustaka. Penelitian terdahulu banyak menegaskan pentingnya konteks framework, tetapi tidak semuanya mewujudkannya dalam artefak operasional yang ringan. Dalam penelitian ini, konteks framework diterjemahkan ke dalam keputusan pemuatan rule. Efek praktisnya terlihat jelas: ketika konteks Laravel tersedia, rule Laravel aktif dan temuan muncul; ketika konteks dihilangkan, rule tersebut tidak dijalankan. Dengan demikian, kontribusi utama penelitian bukan hanya pada jumlah rule, tetapi pada mekanisme pengaitan antara konteks proyek dan aktivasi rule yang relevan.

### 5.3 Implikasi penerapan pada project ini

Dari sudut pandang penerapan, hasil evaluasi ini memperlihatkan kegunaan praktis project ini sebagai alat audit awal untuk codebase PHP. Pada proyek dengan konteks yang jelas, seperti Laravel dan WordPress, artefak mampu menemukan konfigurasi lemah, pola query berbahaya, kelemahan XSS, kelemahan kontrol akses, dan *token/configuration misconfiguration*. Output yang dihasilkan dalam format JSON, SARIF, HTML, dan Markdown membuat hasil scan dapat diarahkan ke kebutuhan audit manual maupun integrasi alat lain. Dengan kata lain, project ini relevan untuk skenario *secure code review*, *pre-merge scanning*, dan pelaporan keamanan berbasis pipeline, walaupun integrasi CI/CD otomatisnya masih perlu disempurnakan.

Uji *workspace scan* pada root repositori memberikan temuan tambahan yang penting secara teknis. Seluruh 12 finding pada scan root berasal dari direktori `research_fixtures`, bukan dari source engine Go VANGUARD. Di saat yang sama, scan root tersebut hanya mengaktifkan rule WordPress dan rule umum. Fakta ini mengindikasikan bahwa implementasi resolver saat ini bekerja dengan asumsi satu konteks dominan per target scan. Implikasi praktisnya adalah pengguna sebaiknya menjalankan VANGUARD pada root proyek PHP yang spesifik, bukan pada *workspace* campuran yang berisi beberapa subproyek atau fixture lintas framework, agar aktivasi rule tetap relevan dan lengkap.

### 5.4 Keterbatasan dan ancaman validitas

Hasil evaluasi juga memperlihatkan batasan yang perlu dicatat secara jujur. Pertama, pengujian efektivitas pada artikel ini masih menggunakan fixture terkontrol, belum dataset benchmark besar atau proyek produksi nyata. Kedua, pendekatan berbasis *regex* dan *pattern matching* belum mampu menggantikan analisis semantik yang lebih dalam seperti *taint tracking* lintas fungsi, *data-flow analysis*, atau *symbolic execution*. Ketiga, beberapa finding yang overlap menunjukkan bahwa *post-processing* dan pengelompokan hasil masih dapat ditingkatkan. Keempat, area CLI, TUI, dan *workflow generator* belum memiliki tingkat pengujian yang setara dengan mesin pemindaian inti. Kelima, *workspace scan* yang mengandung campuran engine dan fixture berisiko menimbulkan pembacaan yang salah jika tidak dibedakan dari evaluasi fixture terkontrol. Keenam, nilai precision, specificity, accuracy, dan F1 yang dilaporkan pada artikel ini masih merupakan *observed metrics under controlled fixtures*, sehingga tetap membutuhkan validasi lanjutan pada benchmark eksternal.

Keterbatasan tersebut justru memperjelas posisi ilmiah penelitian ini. Penelitian ini tidak mengklaim menyelesaikan seluruh persoalan analisis keamanan aplikasi, tetapi menawarkan artefak yang terbukti fungsional, relevan, dan memiliki nilai operasional untuk audit awal pada aplikasi PHP multi-framework. Nilai kebaruan penelitian ini terletak pada integrasi konteks framework, rule keamanan umum dan spesifik framework, pemeriksaan dependensi, histori scan, dan evaluasi berlapis yang menunjukkan efek nyata dari pendekatan *framework-aware* terhadap hasil pemindaian.

### 5.5 Sintesis terhadap rumusan masalah

Jika dikaitkan kembali ke rumusan masalah penelitian, hasil yang diperoleh memberi jawaban yang cukup jelas. Rumusan masalah pertama terjawab melalui implementasi resolver dan orchestrator yang mampu mengenali konteks framework lalu mengaktifkan rule yang sesuai, sebagaimana dibuktikan oleh perbedaan hasil pada `laravel_framework` dan `laravel_generic_clone`. Rumusan masalah kedua terjawab melalui basis rule yang secara aktual terbagi ke dalam rule umum dan rule spesifik framework, dan terbukti aktif pada skenario Laravel serta WordPress yang berbeda secara semantik maupun struktur file.

Rumusan masalah ketiga terjawab melalui integrasi analisis source code, konfigurasi, dependensi, histori scan, dan pelaporan multi-format ke dalam satu alur kerja artefak. Sementara itu, rumusan masalah keempat terjawab secara parsial melalui evaluasi berlapis: pengujian internal menunjukkan kesiapan teknis mesin inti, pengujian fixture menunjukkan efektivitas awal pada skenario terkontrol, dan *workspace scan* menunjukkan perilaku aktual artefak pada repositori penelitian. Dengan demikian, artikel ini tidak hanya mendeskripsikan bahwa artefak telah dibuat, tetapi juga menunjukkan bagaimana artefak diuji, apa yang berhasil dibuktikan, dan batas mana yang masih perlu dikembangkan pada penelitian berikutnya.

## 6. Kesimpulan

Penelitian ini merancang dan mengevaluasi artefak bernama VANGUARD sebagai *framework-aware static security scanner* untuk aplikasi PHP multi-framework. Melalui pendekatan *Design Science Research*, penelitian ini menghasilkan artefak yang mengintegrasikan deteksi konteks framework, basis aturan keamanan umum dan spesifik framework, pemeriksaan dependensi berbasis OSV, histori scan, dan pelaporan multi-format.

Kondisi project saat penelitian menunjukkan bahwa artefak telah berada pada tahap implementasi yang nyata. VANGUARD dibangun dengan Go 1.24.2, mendukung akuisisi source lokal maupun Git, menyediakan mode CLI dan TUI, serta memuat 464 rule keamanan pada 152 berkas YAML. Pada tahap validasi internal, project memiliki 97 *test case* dan seluruh test suite lulus. Pada tahap evaluasi berbasis fixture, seluruh 12 skenario kerentanan yang ditanam pada tiga fixture positif berhasil terdeteksi, seluruh 12 skenario aman pada tiga negative control tidak menghasilkan finding, dan pada dataset terkontrol diperoleh precision, recall, specificity, accuracy, dan F1-score sebesar 100%. Rata-rata waktu pemindaian fixture positif adalah 32.8322 ms. Selain itu, pembandingan antara fixture Laravel yang dikenali framework-nya dan salinan kode yang sama tanpa konteks framework menunjukkan perbedaan hasil 6 finding berbanding 0 finding, yang memperlihatkan efek nyata dari mekanisme *framework-aware*.

Verifikasi pada root *workspace* penelitian juga menunjukkan bahwa artefak dapat dijalankan pada repositori aktual dan menghasilkan 12 finding yang seluruhnya berasal dari `research_fixtures` yang memang sengaja rentan. Hasil ini menegaskan dua hal: pertama, runtime artefak bekerja sesuai desain; kedua, penggunaan alat paling tepat dilakukan pada root proyek yang spesifik karena resolver saat ini cenderung bekerja dengan asumsi satu konteks dominan per target scan.

Kontribusi utama penelitian ini adalah penyusunan model artefak *framework-aware static security scanning* yang ringan, terstruktur, dan terbukti fungsional pada evaluasi awal yang relevan dengan domain PHP. Penelitian lanjutan disarankan untuk memperluas evaluasi ke proyek nyata atau benchmark publik, mengukur *precision* dan *false positive rate* secara lebih formal, meningkatkan *grouping* finding yang overlap, memperkuat dukungan untuk *workspace* multi-proyek, serta menyempurnakan area CLI, TUI, dan integrasi workflow otomatis.

## Daftar Pustaka

[1] OWASP, "OWASP Top 10:2025," 2025. [Online]. Available: https://owasp.org/Top10/2025/

[2] W3Techs, "Usage statistics of PHP for websites," 10 March 2026. [Online]. Available: https://w3techs.com/technologies/details/pl-php

[3] M. Sridharan, S. Artzi, M. Pistoia, S. Guarnieri, O. Tripp, and R. Berg, "F4F: Taint analysis of framework-based web applications," in *Proceedings of OOPSLA 2011*, 2011. [Online]. Available: https://research.ibm.com/publications/f4f-taint-analysis-of-framework-based-web-applications

[4] A. Agrawal, M. Alenezi, R. Kumar, and R. A. Khan, "Securing Web Applications through a Framework of Source Code Analysis," *Journal of Computer Science*, vol. 15, no. 12, pp. 1780-1794, 2019. doi: 10.3844/jcssp.2019.1780.1794

[5] J. Zhao, K. Zhu, C. Lu, J. Zhao, and Y. Lu, "Benchmarking Static Analysis for PHP Applications Security," *Entropy*, vol. 27, no. 9, art. no. 926, 2025. doi: 10.3390/e27090926

[6] OSV, "Open Source Vulnerabilities," 2026. [Online]. Available: https://osv.dev/ and https://google.github.io/osv.dev/api/

[7] A. R. Hevner, S. T. March, J. Park, and S. Ram, "Design Science in Information Systems Research," *MIS Quarterly*, vol. 28, no. 1, pp. 75-105, 2004. [Online]. Available: https://www.hec.edu/en/faculty-research/centers/hi-paris-center/articles/design-science-information-systems-research

[8] OWASP, "OWASP Top 10:2021," 2021. [Online]. Available: https://owasp.org/Top10/2021/

# 🛡️ BINMAS Command Center

**Sistem Manajemen & Monitoring Satpam Sumatera Selatan**

> Web Application Command Center untuk manajemen satpam, absensi geolokasi, monitoring realtime, dan sistem darurat terintegrasi.

---

## ✨ Fitur Utama

| Modul | Fitur | Status |
|-------|-------|--------|
| 🔐 **Keamanan** | Autentikasi PBKDF2 SHA256 260k iterasi | ✅ |
| | Anti Brute Force Protection (12x gagal = blokir 45 menit) | ✅ |
| | Rate Limiter 800 request/menit | ✅ |
| | Audit Log lengkap semua aktifitas | ✅ |
| | Multi Role Permission System | ✅ |
| 🧑💼 **Manajemen** | Manajemen Data BUJP (Badan Usaha Jasa Pengamanan) | ✅ |
| | Profil Anggota & Satpam Lengkap | ✅ |
| | Perpanjangan KTA Online dengan Workflow Approval | ✅ |
| | Sistem Pembayaran KTA dengan Upload Bukti Transfer | ✅ |
| ✅ **Absensi** | Absensi Masuk/Keluar dengan Geolocation GPS | ✅ |
| | Sistem Sesi Absensi Admin Controlled | ✅ |
| | Geofence Absensi dengan Radius Dapat Dikonfigurasi | ✅ |
| | Rekap Absensi & Laporan Export | ✅ |
| 🚨 **Emergency** | Tombol Panik Satpam Lokasi Realtime | ✅ |
| | Upload Foto Bukti Laporan Darurat | ✅ |
| | Dashboard Monitor Emergency Live | ✅ |
| | Notifikasi Realtime Untuk Admin | ✅ |
| 📍 **Monitoring** | Live Tracking Lokasi Satpam Realtime | ✅ |
| | Maps OpenStreetMap Leaflet.js | ✅ |
| | Heatmap Aktifitas Lokasi | ✅ |
| | Geofence Management Polygon | ✅ |
| | Cluster Marker | ✅ |
| 🎨 **UI/UX** | Responsive Mobile First Design | ✅ |
| | Dark Mode Modern Glassmorphism | ✅ |
| | PWA Support (Install sebagai Aplikasi) | ✅ |
| ⚡ **Performa** | Thread Safe Design | ✅ |
| | Support 200+ User Concurrent | ✅ |
| | SQLite WAL Mode Optimasi | ✅ |
| | Auto Database Migration | ✅ |

---

## 📋 Persyaratan Sistem

| Komponen | Versi Minimum |
|----------|---------------|
| Python | 3.8+ |
| RAM | 512 MB |
| Storage | 100 MB |
| OS | Windows 10+, Linux, macOS |

## 🚀 Instalasi

### 1. Clone / Download Project
```bash
cd experimental
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Jalankan Aplikasi
```bash
python binmas.py
```

Aplikasi akan berjalan di `http://localhost:5000`

---

## ⚙️ Konfigurasi Environment

Buat file `.env` di folder experimental untuk mengatur custom password:

```env
# Password Default Akun
ADMIN_PASS=password_admin_disini
DIREKTUR_PASS=password_direktur_disini
SATPAM_DEFAULT_PASS=password_satpam_disini
ANGGOTA_DEFAULT_PASS=password_anggota_disini

# Secret Key Aplikasi
SECRET_KEY=random_string_32_character_disini
```

---

## 👤 Default Akun

Saat pertama kali dijalankan, aplikasi akan membuat akun default secara otomatis:

| Username | Role | Password Default |
|----------|------|------------------|
| `admin` | Administrator | *Random di generate saat first run* |
| `direktur` | Direktur Binmas | *Random di generate saat first run* |
| `satpam1` | Satpam | *Random di generate saat first run* |
| `anggota1` | Anggota | *Random di generate saat first run* |

> ✅ Password akan ditampilkan di console saat pertama kali menjalankan aplikasi. Catat password tersebut!

---

## 🗄️ Struktur Database

| Tabel | Fungsi |
|-------|--------|
| `users` | Data pengguna & autentikasi |
| `bujp` | Data Badan Usaha Jasa Pengamanan |
| `kta_perpanjangan` | Pengajuan perpanjangan KTA |
| `absensi` | Data absensi masuk/keluar |
| `absensi_sesi` | Sesi absensi yang diatur admin |
| `locations` | Log lokasi pengguna realtime |
| `geofences` | Data area geofence polygon |
| `emergency_reports` | Laporan darurat satpam |
| `audit_logs` | Log semua aktifitas sistem |
| `admin_notifications` | Notifikasi admin |
| `rekening_bank` | Daftar rekening pembayaran |

---

## 📡 API Endpoint

| Method | Path | Keterangan |
|--------|------|------------|
| `GET` | `/` | Halaman Login |
| `POST` | `/login` | Proses login |
| `GET` | `/admin/dashboard` | Dashboard Admin |
| `GET` | `/monitor/map` | Monitor Lokasi Realtime |
| `GET` | `/satpam` | Halaman Satpam |
| `POST` | `/api/emergency/report` | Kirim laporan darurat |
| `POST` | `/api/absensi/submit` | Submit absensi |
| `WS` | `/ws/monitor` | Websocket realtime monitor |

---

## 🛠️ Troubleshooting

### ❌ Masalah Encoding Windows
Jika muncul error karakter aneh di console:
> Aplikasi sudah otomatis mengatur encoding UTF-8 untuk Windows. Pastikan menggunakan Python 3.7+

### ❌ Tidak bisa buka maps
Pastikan koneksi internet aktif, karena Leaflet.js mengambil tile dari OpenStreetMap.

### ❌ Error Database Locked
Restart aplikasi. Sistem menggunakan WAL mode yang meminimalisir lock.

---

## 📝 Catatan Teknis

- Timezone default: **WIB (UTC+7)** semua waktu otomatis dikonversi
- Semua data waktu disimpan dalam UTC di database
- Log error tersimpan di file `binmas_errors.log`
- Database file: `app.db` (SQLite3)
- Max session login: 8 jam

---

## 🔄 Changelog

### v3.0.0 Terbaru
✅ Implementasi sistem sesi absensi
✅ Sistem pembayaran KTA
✅ Anti brute force thread safe
✅ Optimasi performa 200 user concurrent
✅ UI/UX Redesign modern glassmorphism
✅ PWA Support
✅ Emergency alert system

---

## 👨💻 Development

Developed By Devin Dimas Mahendra

> **⚠️ Catatan:** Aplikasi ini hanya untuk penggunaan internal. Dilarang menyebarkan atau memodifikasi tanpa izin.

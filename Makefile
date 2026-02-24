# --- Konfigurasi Dasar ---
TARGET_NAME = halmos
BIN_DIR = bin
SRC_DIR = src
OBJ_DIR = build
INC_DIR = include
RUNTIME_DIR = runtime
SERVICE_NAME = halmos.service

TARGET = $(BIN_DIR)/$(TARGET_NAME)
VERSION := $(shell cat VERSION 2>/dev/null || echo "0.2.4")

# Path Sistem
DEST_BIN     = /usr/bin/$(TARGET_NAME)
DEST_CONF    = /etc/halmos
DEST_SERVICE = /etc/systemd/system/$(SERVICE_NAME)
DEST_WWW     = /var/www

# Path Sistem (Tambahan)
DEST_HTML   = $(DEST_WWW)/html
DEST_PY     = $(DEST_WWW)/halmos-python
DEST_RUST   = $(DEST_WWW)/halmos-rust

# Compiler
CC = gcc
CFLAGS = -Wall -Wextra -O3 -I$(INC_DIR) -I$(INC_DIR)/halmos -DVERSION=\"$(VERSION)\" -D_GNU_SOURCE
LDFLAGS = -lpthread -lm -lssl -lcrypto -ljson-c

SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	@$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

# ---------------------------------------------------------
# 1. INSTALL: Cuma copy file ke folder sistem (Tanpa Start)
# ---------------------------------------------------------
install: all
	@echo "[INSTALL] Menyiapkan struktur direktori di $(DEST_WWW)..."
# -p artinya: buat jika belum ada, abaikan jika sudah ada
	sudo mkdir -p $(DEST_HTML)
	sudo mkdir -p $(DEST_PY)
	sudo mkdir -p $(DEST_RUST)
	sudo mkdir -p $(DEST_CONF)

	@echo "[INSTALL] Menyalin file program dan konfigurasi..."
	sudo install -m 755 $(TARGET) $(DEST_BIN)
	sudo install -m 644 $(RUNTIME_DIR)/configs/halmos.conf $(DEST_CONF)/
	sudo install -m 644 $(RUNTIME_DIR)/configs/$(SERVICE_NAME) $(DEST_SERVICE)

	@echo "[INSTALL] Menyalin konten web ke $(DEST_HTML)..."
# 	Copy folder halmos-example (beserta isinya)
	sudo cp -r $(RUNTIME_DIR)/www/html/halmos-example $(DEST_HTML)/
# 	Copy file index.html
	sudo cp $(RUNTIME_DIR)/www/html/index.html $(DEST_HTML)/

	@echo "[INSTALL] Menyalin skrip Backend (Python & Rust)..."
# 	Copy isi folder python ke /var/www/halmos-python
# 	Gunakan -r agar subfolder dan file di dalamnya ikut semua
	sudo cp -r $(RUNTIME_DIR)/www/halmos-python/* $(DEST_PY)/
	
# 	Copy isi folder rust ke /var/www/halmos-rust
	sudo cp -r $(RUNTIME_DIR)/www/halmos-rust/* $(DEST_RUST)/

	@echo "[INSTALL] Mendaftarkan service ke sistem..."
	sudo systemctl daemon-reload
	@echo "[OK] Semua file web dan backend telah terpasang!"
	@echo "[INFO] Gunakan 'make run' untuk menjalankan di background."
	@echo "       Atau 'make debug' untuk menjalankan di terminal."

# ---------------------------------------------------------
# 2. RUN: Jalankan sebagai service background (Systemd)
# ---------------------------------------------------------
run:
	@echo "[RUN] Menjalankan Halmos di background (Systemd)..."
	-sudo systemctl stop $(TARGET_NAME) 2>/dev/null || true
	sudo systemctl start $(TARGET_NAME)
	@echo "[OK] Halmos Service Aktif!"
	@systemctl status $(TARGET_NAME) | grep -E "Active|Main PID|Tasks|Memory"

# ---------------------------------------------------------
# 3. DEBUG: Jalankan di terminal (Foreground) + Cek Background
# ---------------------------------------------------------
debug: all
	@echo "[CHECK] Memeriksa konflik background..."
	@if systemctl is-active --quiet $(TARGET_NAME); then \
		echo "--------------------------------------------------------"; \
		echo "WARNING: Ada Halmos versi BACKGROUND yang lagi jalan!"; \
		echo "Matiin dulu bos, biar nggak bentrok port-nya."; \
		echo "Ketik: sudo systemctl stop halmos"; \
		echo "--------------------------------------------------------"; \
		exit 1; \
	fi
	@if pgrep -x "$(TARGET_NAME)" > /dev/null; then \
		echo "WARNING: Ada proses Halmos liar (zombie) ditemukan!"; \
		echo "Gue bersihin dulu ya..."; \
		sudo killall -9 $(TARGET_NAME); \
	fi
	@echo "[DEBUG] Memulai Halmos v$(VERSION) di terminal..."
	sudo ./$(TARGET)

# ---------------------------------------------------------
# 4. CLEAN: Uninstall total & Bersihkan build
# ---------------------------------------------------------
clean:
	@echo "[CLEAN] Menghapus build files & Uninstall dari sistem..."
	-sudo systemctl stop $(TARGET_NAME) 2>/dev/null || true
	-sudo systemctl disable $(TARGET_NAME) 2>/dev/null || true
	sudo rm -rf $(OBJ_DIR) $(BIN_DIR)
	sudo rm -f $(DEST_BIN)
	sudo rm -f $(DEST_SERVICE)
	sudo rm -f $(DEST_CONF)/halmos.conf
	sudo systemctl daemon-reload
	@echo "[OK] Program Bersih total!"

.PHONY: all install run debug clean
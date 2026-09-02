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

# Warna untuk output terminal
GREEN  = \033[0;32m
YELLOW = \033[0;33m
BLUE   = \033[0;34m
NC     = \033[0m # No Color

# Path Sistem
DEST_BIN     = /usr/bin/$(TARGET_NAME)
DEST_CONF    = /etc/halmos
DEST_SERVICE = /etc/systemd/system/$(SERVICE_NAME)
DEST_WWW     = /var/www
DEST_LOG     = /var/log/halmos

# Sub-folder WWW
DEST_HTML   = $(DEST_WWW)/html
DEST_PY     = $(DEST_WWW)/halmos-python
DEST_RUST   = $(DEST_WWW)/halmos-rust

# Path Sertifikat TLS (Sesuai halmos.conf)
CERT_KEY = $(DEST_CONF)/halmos_server.key
CERT_CRT = $(DEST_CONF)/halmos_server.crt

# Compiler & Flags Base
CC = gcc
CFLAGS = -Wall -Wextra -g -O0 -I$(INC_DIR) -I$(INC_DIR)/halmos -DVERSION=\"$(VERSION)\" -D_GNU_SOURCE
LDFLAGS = -lpthread -lm -lssl -lcrypto -ljson-c

# Pencarian Source Files secara otomatis
SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

# ---------------------------------------------------------
# TARGET UTAMA (Default: ketik 'make' saja)
# ---------------------------------------------------------
all: $(TARGET)
	@echo "$(GREEN)==================================================$(NC)"
	@echo "$(GREEN) [SUCCESS] Halmos v$(VERSION) Build Selesai!$(NC)"
	@echo " Lokasi Binari: $(TARGET)"
	@echo "$(GREEN)==================================================$(NC)"
	@echo "Ketik 'sudo make install' untuk memasang ke sistem."

# Proses Linking (Mencakup LDFLAGS + Sanitizer LDFLAGS jika ada)
$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	@echo "$(BLUE)[LINK]$(NC) Menyatukan semua modul menjadi $(TARGET)..."
	@$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Proses Kompilasi per file .c
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	@echo "$(YELLOW)[CC]$(NC) Mengompilasi: $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# ---------------------------------------------------------
# 1. SANITIZERS (ASan & TSan profiling)
# ---------------------------------------------------------

# Target ASan (AddressSanitizer untuk Memory Leaks & Buffer Overflow)
asan: CFLAGS += -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer
asan: LDFLAGS += -fsanitize=address -fsanitize=undefined
asan: reall
	@echo "$(GREEN)[ASan] Build berhasil disiapkan dengan AddressSanitizer!$(NC)"
	@echo "Jalankan 'sudo ./bin/halmos' atau 'make debug' untuk analisis memory."

# Target TSan (ThreadSanitizer untuk Data Race & Concurrency Bug)
tsan: CFLAGS += -fsanitize=thread -fno-omit-frame-pointer
tsan: LDFLAGS += -fsanitize=thread
tsan: reall
	@echo "$(GREEN)[TSan] Build berhasil disiapkan dengan ThreadSanitizer!$(NC)"
	@echo "Jalankan 'sudo ./bin/halmos' atau 'make debug' untuk analisis data race."

# Internal helper untuk hapus build lama saat mengaktifkan Sanitizer
reall: clean-build all

clean-build:
	@rm -rf $(OBJ_DIR) $(BIN_DIR)

# ---------------------------------------------------------
# 2. INSTALL: Pasang ke folder sistem
# ---------------------------------------------------------
install: all
	@echo "$(BLUE)[INSTALL]$(NC) Membuat struktur direktori..."
	sudo mkdir -p $(DEST_HTML) $(DEST_PY) $(DEST_RUST) $(DEST_CONF) $(DEST_LOG)
	sudo chmod 755 $(DEST_LOG)

	@echo "$(BLUE)[INSTALL]$(NC) Menyalin binari dan konfigurasi..."
	sudo install -m 755 $(TARGET) $(DEST_BIN)
	sudo install -m 644 $(RUNTIME_DIR)/configs/halmos.conf $(DEST_CONF)/
	sudo install -m 644 $(RUNTIME_DIR)/configs/$(SERVICE_NAME) $(DEST_SERVICE)

	@echo "$(BLUE)[INSTALL]$(NC) Memeriksa kunci & sertifikat TLS..."
	@if [ ! -f $(CERT_KEY) ] || [ ! -f $(CERT_CRT) ]; then \
		echo "$(YELLOW)[TLS]$(NC) Kunci TLS tidak ditemukan. Generate Self-Signed otomatis..."; \
		sudo openssl req -x509 -newkey rsa:2048 -keyout $(CERT_KEY) -out $(CERT_CRT) \
			-sha256 -days 365 -nodes -subj "/CN=HalmosServer/O=Halmos Web Server" > /dev/null 2>&1; \
		sudo chmod 600 $(CERT_KEY); \
		sudo chmod 644 $(CERT_CRT); \
		echo "$(GREEN)[TLS]$(NC) Sertifikat bawaan berhasil dibuat di $(DEST_CONF)/"; \
	else \
		echo "$(GREEN)[TLS]$(NC) Kunci TLS sudah ada, melewati pembuatan sertifikat."; \
	fi

	@echo "$(BLUE)[INSTALL]$(NC) Menyalin konten web & backend secara aman..."
	sudo cp -a $(RUNTIME_DIR)/www/html/halmos-example $(DEST_HTML)/
	sudo install -m 644 $(RUNTIME_DIR)/www/html/index.html $(DEST_HTML)/index.html
	sudo cp -a $(RUNTIME_DIR)/www/halmos-python/. $(DEST_PY)/
	sudo cp -a $(RUNTIME_DIR)/www/halmos-rust/. $(DEST_RUST)/

	@echo "$(BLUE)[INSTALL]$(NC) Mendaftarkan service ke systemd..."
	sudo systemctl daemon-reload
	@echo "\n$(GREEN)[OK] Halmos terpasang sempurna!$(NC)"
	@echo "Gunakan 'make run' untuk jalan di background."
	@echo "Atau 'make debug' untuk jalan di terminal."

# ---------------------------------------------------------
# 3. RUN: Jalankan sebagai service (Background)
# ---------------------------------------------------------
run:
	@echo "$(BLUE)[RUN]$(NC) Memulai layanan Halmos..."
	-sudo systemctl stop $(TARGET_NAME) 2>/dev/null || true
	sudo systemctl start $(TARGET_NAME)
	@systemctl status $(TARGET_NAME) | grep -E "Active|Main PID"

# ---------------------------------------------------------
# 4. DEBUG: Jalankan di Foreground (Terminal)
# ---------------------------------------------------------
debug: all
	@echo "$(YELLOW)[CHECK]$(NC) Memeriksa konflik..."
	@if systemctl is-active --quiet $(TARGET_NAME); then \
		echo "Matikan service dulu: sudo systemctl stop halmos"; \
		exit 1; \
	fi
	sudo ./$(TARGET)

# ---------------------------------------------------------
# 5. CLEAN: Hapus file build & Uninstall dari sistem
# ---------------------------------------------------------
clean:
	@echo "$(YELLOW)[CLEAN]$(NC) Menghapus build files & Uninstall..."
	-sudo systemctl stop $(TARGET_NAME) 2>/dev/null || true
	sudo rm -rf $(OBJ_DIR) $(BIN_DIR)
	sudo rm -f $(DEST_BIN) $(DEST_SERVICE) $(DEST_CONF)/halmos.conf
	sudo systemctl daemon-reload
	@echo "$(GREEN)[OK] Bersih total!$(NC)"

.PHONY: all install run debug clean asan tsan reall clean-build
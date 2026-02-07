# Nama program
TARGET_NAME = halmos

# Ambil versi dan bersihkan
VERSION := $(shell cat VERSION | tr -d '\r\n' | xargs 2>/dev/null || echo "0.0.1")

# Direktori Proyek
BIN_DIR = bin
SRC_DIR = src
OBJ_DIR = build
INC_DIR = include
RUNTIME_DIR = runtime
SERVICE_NAME = halmos.service

TARGET = $(BIN_DIR)/$(TARGET_NAME)

# Path Destinasi Sistem (Langsung ke /etc sesuai permintaanmu)
DEST_BIN     = /usr/bin/$(TARGET_NAME)
DEST_CONF    = /etc/halmos
DEST_SERVICE = /etc/systemd/system/$(SERVICE_NAME)
DEST_WWW     = /var/www/halmos

# Compiler dan Flags
CC = gcc
INC_FLAGS = -I$(INC_DIR) -I$(INC_DIR)/halmos
CFLAGS = -Wall -Wextra -O3 $(INC_FLAGS) -DVERSION=\"$(VERSION)\" -D_GNU_SOURCE
LDFLAGS = -lpthread -lm

# Mencari semua file .c secara rekursif
SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

# --- Rules ---

all: $(TARGET)

# Linker
$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	@echo "Linking binary: $(TARGET)..."
	@$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo "Build version $(VERSION) complete."

# Kompilasi Source ke Objects
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

# 1. Install: Copy semua file ke folder sistem (TARGET: /etc)
install: all
	@echo "Installing Halmos v$(VERSION) to /etc/systemd/system/..."
	
	# Bersihkan file lama di /lib jika pernah ada supaya tidak bentrok
	sudo rm -f /lib/systemd/system/$(SERVICE_NAME)
	
	# Install Binary
	sudo install -d $(DESTDIR)/usr/bin
	sudo install -m 755 $(TARGET) $(DESTDIR)$(DEST_BIN)
	
	# Install Konfigurasi
	sudo install -d $(DESTDIR)$(DEST_CONF)
	sudo install -m 644 $(RUNTIME_DIR)/configs/halmos.conf $(DESTDIR)$(DEST_CONF)/
	
	# Install Systemd Service LANGSUNG KE /ETC
	sudo install -d $(DESTDIR)/etc/systemd/system
	sudo install -m 644 $(RUNTIME_DIR)/configs/$(SERVICE_NAME) $(DESTDIR)$(DEST_SERVICE)
	
	# Install Web Assets
	sudo install -d $(DESTDIR)$(DEST_WWW)
	sudo cp -r $(RUNTIME_DIR)/examples/* $(DESTDIR)$(DEST_WWW)/
	
	# Atur Izin Akses
	sudo chmod -R 755 $(DESTDIR)$(DEST_WWW)
	
	@echo "--------------------------------------------------------"
	@echo "Selesai! File service ada di: /etc/systemd/system/halmos.service"
	@echo "--------------------------------------------------------"
	@echo "Jalankan perintah ini untuk mengaktifkan:"
	@echo "sudo systemctl daemon-reload"
	@echo "sudo systemctl enable halmos"
	@echo "sudo systemctl start halmos"

# 2. Uninstall: Hapus semua jejak dari sistem
uninstall:
	@echo "Uninstalling Halmos..."
	
	# Matikan service dulu
	-sudo systemctl stop $(TARGET_NAME)
	-sudo systemctl disable $(TARGET_NAME)
	
	# Hapus Binary, Config, dan Service
	sudo rm -f $(DEST_BIN)
	sudo rm -f $(DEST_SERVICE)
	sudo rm -rf $(DEST_CONF)
	sudo rm -rf $(DEST_WWW)
	
	# Hapus sisa symlink di folder wants
	sudo rm -f /etc/systemd/system/multi-user.target.wants/$(SERVICE_NAME)
	
	# Reload systemd agar bersih
	sudo systemctl daemon-reload
	
	@echo "Uninstall selesai! Bersih total."

clean:
	@echo "Cleaning up build directories..."
	@rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "Cleaned."

.PHONY: all clean run install uninstall
# Nama program
TARGET_NAME = halmos

# Ambil versi dan bersihkan dari karakter aneh/spasi
VERSION := $(shell cat VERSION | tr -d '\r\n' | xargs)

# Tambahkan pengecekan jika VERSION kosong agar tidak error
ifeq ($(VERSION),)
  VERSION := 0.0.1
endif

# Direktori
BIN_DIR = bin
SRC_DIR = src
OBJ_DIR = build
INC_DIR = include
RUNTIME_DIR = runtime

TARGET = $(BIN_DIR)/$(TARGET_NAME)

# Compiler dan Flags
CC = gcc
# Mencari semua folder di dalam include secara otomatis
INC_FLAGS = -I$(INC_DIR) -I$(INC_DIR)/halmos

# CFLAGS dengan dukungan untuk header dan macro versi
CFLAGS = -Wall -Wextra -O3 $(INC_FLAGS) -DVERSION=\"$(VERSION)\" -D_GNU_SOURCE
LDFLAGS = -lpthread -lm

# Mencari semua file .c secara rekursif di dalam src/
# Ini akan otomatis menemukan src/main.c, src/core/*.c, src/fastcgi/*.c, dll.
SRCS := $(shell find $(SRC_DIR) -name '*.c')

# Mengubah path src/xxx.c menjadi build/xxx.o
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

# Install Standar Linux (untuk distribusi .deb)
# Perhatikan penggunaan DESTDIR untuk keperluan packaging
install: all
	@echo "Installing to system..."
	# 1. Install Binary Utama
	install -d $(DESTDIR)/usr/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/bin/$(TARGET_NAME)
	
	# 2. Install konfigurasi
	install -d $(DESTDIR)/etc/halmos
	install -m 644 $(RUNTIME_DIR)/configs/halmos.conf $(DESTDIR)/etc/halmos/
	
	# 3. Install Web Assets (HTML, PHP, Python, Rust) ke /var/www/halmos
	install -d $(DESTDIR)/var/www/halmos
	cp -r $(RUNTIME_DIR)/examples/* $(DESTDIR)/var/www/halmos/
	

	# 4. Atur Izin Akses
	# Folder web harus bisa dibaca, tapi backend harus aman
	chmod -R 755 $(DESTDIR)/var/www/halmos
	@echo "Install selesai! Cek folder /var/www/halmos"
clean:
	@echo "Cleaning up..."
	@rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "Cleaned."

run: all
	@echo "Starting $(TARGET_NAME) v$(VERSION)..."
	@./$(TARGET)

.PHONY: all clean run install

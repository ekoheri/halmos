CC = gcc
CFLAGS = -Wall -Iinclude
LDFLAGS = -lm

# Direktori
SRC_DIR = src
OBJ_DIR = build
BIN_DIR = bin
ETC_DIR = /etc/halmos
LOG_DIR  = /var/log/halmos
HTML_SOURCE_DIR = html
HTML_DEST_DIR = /var/www/html/halmos

# File sumber dan objek
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))
TARGET = $(BIN_DIR)/halmos
CONFIG_FILE = config/halmos.conf

# Aturan utama
all: $(TARGET)

# Membuat executable
$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Membuat file objek
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

install: all
	@mkdir -p $(ETC_DIR)
#	@chmod 0777 $(ETC_DIR)
	@cp $(CONFIG_FILE) $(ETC_DIR)
	@mkdir -p $(HTML_DEST_DIR)
	@chmod 0777 $(HTML_DEST_DIR)
	@cp -r $(HTML_SOURCE_DIR)/* $(HTML_DEST_DIR)
	@mkdir -p $(LOG_DIR)
	@chmod 0777 $(LOG_DIR)
#	@cp $(TARGET) /usr/local/bin/

# Membersihkan file hasil kompilasi
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# Membersihkan lebih lengkap (opsional)
dist-clean: clean
	rm -rf $(HTML_DEST_DIR)/*
	rm -rf $(TARGET)
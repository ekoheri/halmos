CC = gcc
# MODIFIKASI DI SINI: Kita cari semua sub-folder di dalam include secara otomatis
INCLUDE_DIRS = $(shell find include -type d)
# Tambahkan awalan -I ke setiap folder yang ditemukan
CFLAGS = -Wall $(addprefix -I,$(INCLUDE_DIRS)) -pthread
LDFLAGS = -pthread -lm -lbrotlienc -lbrotlidec -lbrotlicommon -lpng

# Direktori
SRC_DIR = src
OBJ_DIR = build
BIN_DIR = bin
BIN_DEST = /usr/local/bin/halmos
SYSTEMD_DIR = /etc/systemd/system
ETC_DIR = /etc/halmos
LOG_DIR = /var/log/halmos
HTML_SOURCE_DIR = html
HTML_DEST_DIR = /var/www/html/halmos
SERVICE_FILE = config/halmos.service

# File sumber dan objek
SRCS = $(shell find $(SRC_DIR) -name "*.c")
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))
TARGET = $(BIN_DIR)/halmos
CONFIG_FILE = config/halmos.conf

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

install: all
	@echo "Installing Halmos Engine..."
	@mkdir -p $(ETC_DIR)
	@cp $(CONFIG_FILE) $(ETC_DIR)
	@mkdir -p $(HTML_DEST_DIR)
	@chmod 0777 $(HTML_DEST_DIR)
	@cp -r $(HTML_SOURCE_DIR)/* $(HTML_DEST_DIR)
	@mkdir -p $(LOG_DIR)
	@chmod 0777 $(LOG_DIR)
	# 1. Copy binary ke folder bin sistem
	@cp $(TARGET) $(BIN_DEST)
	@chmod +x $(BIN_DEST)
	# 2. Copy file service ke folder systemd
	@echo "Installing systemd service..."
	@cp $(SERVICE_FILE) $(SYSTEMD_DIR)/
	# 3. Reload systemd
	@systemctl daemon-reload
	@echo "Install complete. Use 'sudo systemctl start halmos' to run."

clean:
	@echo "Uninstalling Halmos from system..."
	@systemctl stop halmos || true
	@systemctl disable halmos || true
	@rm -f $(SYSTEMD_DIR)/halmos.service
	@systemctl daemon-reload
	@rm -f $(BIN_DEST)
	@rm -rf $(ETC_DIR)
	@rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "Cleanup and Uninstall complete."

dist-clean: clean
	rm -rf $(HTML_DEST_DIR)/*
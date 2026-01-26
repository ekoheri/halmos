# Nama executable
TARGET_NAME = halmos
BIN_DIR = bin
TARGET = $(BIN_DIR)/$(TARGET_NAME)

# Compiler dan Flag
CC = gcc
# Mencari semua subfolder di dalam include secara otomatis
INC_DIRS := $(shell find $(INC_DIR) -type d)
# Menambahkan prefix -I ke setiap folder yang ditemukan
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

# Gunakan INC_FLAGS di dalam CFLAGS
CFLAGS = -Wall -Wextra -O3 $(INC_FLAGS)

#LDFLAGS = -pthread -lm -lbrotlienc -lbrotlidec -lbrotlicommon -lpng

LDFLAGS = -lpthread -lm


# Folder Sumber
SRC_DIR = src
OBJ_DIR = build

# Mencari semua file .c secara rekursif
SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Default Rule
all: $(TARGET)

# Rule Linker (Ini secara teknis sudah melakukan 'install' ke folder bin)
$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	@echo "Linking binary to $(TARGET)..."
	@$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo "Build complete."

# Target Install (Sesuai permintaan Anda: hanya memastikan bin siap)
install: all
	@echo "Installing binary locally in $(BIN_DIR)..."
	@chmod +x $(TARGET)
	@echo "Done. Binary is ready at $(TARGET)"

# Kompilasi file .c menjadi .o
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -D_GNU_SOURCE -c $< -o $@

# Membersihkan hasil build
clean:
	@echo "Cleaning up..."
	@rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "Cleaned."

# Jalankan server
run: all
	@echo "Starting $(TARGET_NAME)..."
	@./$(TARGET)

.PHONY: all clean run install
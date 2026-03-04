CC      := gcc
TARGET  := server

SRC_DIR := src
INC_DIR := include
TP_DIR  := third_party
BUILD   := build

SRCS := \
  $(SRC_DIR)/main.c \
  $(SRC_DIR)/http.c \
  $(SRC_DIR)/db.c \
  $(SRC_DIR)/json_utils.c \
  $(SRC_DIR)/token.c \
  $(SRC_DIR)/auth.c \
  $(SRC_DIR)/door_tcp.c\
  $(SRC_DIR)/crypto.c \
  $(TP_DIR)/mongoose.c


OBJS := $(patsubst %.c,$(BUILD)/%.o,$(SRCS))

CFLAGS  := -O2 -Wall -Wextra -DMG_TLS=MG_TLS_BUILTIN \
           -I$(INC_DIR) -I$(TP_DIR) \
           $(shell mariadb_config --cflags)

LDLIBS  := $(shell mariadb_config --libs) -lcrypto

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDLIBS)

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD) $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run


OUT := xiaomi_adb

CFLAGS := -O2 -Wall -g -I./lib `pkg-config --cflags libusb-1.0 libcurl`
LDFLAGS := `pkg-config --libs libusb-1.0 libcurl`
prefix := /usr/local

SRCS := main.c lib/AES/aes.c lib/BASE64/base64.c lib/JSON/tiny-json.c lib/MD5/md5.c 
OBJS := $(SRCS:.c=.o)

default: $(OUT)

$(OUT): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OUT) $(OBJS)
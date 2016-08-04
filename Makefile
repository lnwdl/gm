CC = gcc
CFLAG = -c -W -Wall -Wpointer-arith -Wno-unused-parameter -Wunused-function -Wunused-variable -Wunused-value -Werror -g 
#CFLAG += -DSHOW_DEBUG_PUB
#CFLAG += -DSHOW_DEBUG_SM3
#CFLAG += -DSHOW_DEBUG_ECS
#CFLAG += -DSHOW_DEBUG_ECH
#CFLAG += -DSHOW_DEBUG_ECE
TARGET = test
#INC_DIR = -I ~/openssl/soft/include
#LD_DIR = -L ~/openssl/soft/lib
SRC_DIR = .
LD_FILE = -lcrypto

SRCS = $(notdir $(wildcard $(SRC_DIR)/*.c))

OBJS = $(patsubst %.c, %.o, $(SRCS))

%.o: $(join $(SRC_DIR)/, %.c)
	$(CC) -c $(CFLAG) $< -o $@ $(INC_DIR) $(LD_DIR)

all: dclean $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LD_DIR) $(LD_FILE)
	@echo "compile && link .......... OK"

clean: 
	rm -rf $(OBJS)

dclean: 
	rm -rf $(OBJS) $(TARGET)


IMAGE_NAME      = shellcode-build-pipeline:latest

SRC_DIR         = src
BUILD_DIR       = build
TOOLS_DIR       = tools

CC              = x86_64-w64-mingw32-gcc
PYTHON          = python3

C_SRC           = $(SRC_DIR)/shellcode.c
ASM_OUT         = $(BUILD_DIR)/c-shellcode.s
CLEAN_ASM_OUT   = $(BUILD_DIR)/c-shellcode_cleaned.asm
SHELL_OBJ       = $(BUILD_DIR)/c-shellcode.o
SHELL_EXE       = $(BUILD_DIR)/c-shellcode.exe
SHELL_BIN       = $(BUILD_DIR)/c-shellcode_64_encoded.bin

CFLAGS_ASM      = -std=c11 -O2 -Wall \
                  -S -masm=intel \
                  -fno-asynchronous-unwind-tables \
                  -fno-stack-protector \
                  -ffreestanding

ASFLAGS_CLEAN   = -c -x assembler-with-cpp
LDFLAGS_PE      = -O2 -Wall -nostdlib -nodefaultlibs -Wl,--entry=AlignRSP

.PHONY: all asm cleaned_asm pe shellcode clean \
        docker-build docker-asm docker-cleaned-asm docker-pe docker-shellcode docker-clean

all: shellcode

asm: $(ASM_OUT)

cleaned_asm: $(CLEAN_ASM_OUT)

pe: $(SHELL_EXE)

shellcode: $(SHELL_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(ASM_OUT): $(C_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS_ASM) -o $@ $(C_SRC)

$(CLEAN_ASM_OUT): $(ASM_OUT) $(TOOLS_DIR)/handle_asm.py | $(BUILD_DIR)
	$(PYTHON) $(TOOLS_DIR)/handle_asm.py clean $(ASM_OUT) $(CLEAN_ASM_OUT)

$(SHELL_OBJ): $(CLEAN_ASM_OUT) | $(BUILD_DIR)
	$(CC) $(ASFLAGS_CLEAN) -o $@ $(CLEAN_ASM_OUT)

$(SHELL_EXE): $(SHELL_OBJ) | $(BUILD_DIR)
	$(CC) $(LDFLAGS_PE) -o $@ $(SHELL_OBJ)

$(SHELL_BIN): $(SHELL_EXE) $(TOOLS_DIR)/handle_asm.py | $(BUILD_DIR)
	$(PYTHON) $(TOOLS_DIR)/handle_asm.py extract $(SHELL_EXE) $(SHELL_BIN)

clean:
	rm -rf $(BUILD_DIR)

docker-build:
	docker build -t $(IMAGE_NAME) .

docker-asm: docker-build
	docker run --rm -v $(PWD):/workspace -w /workspace $(IMAGE_NAME) \
		make asm

docker-cleaned-asm: docker-build
	docker run --rm -v $(PWD):/workspace -w /workspace $(IMAGE_NAME) \
		make cleaned_asm

docker-pe: docker-build
	docker run --rm -v $(PWD):/workspace -w /workspace $(IMAGE_NAME) \
		make pe

docker-shellcode: docker-build
	docker run --rm -v $(PWD):/workspace -w /workspace $(IMAGE_NAME) \
		make shellcode

docker-clean:
	docker rmi $(IMAGE_NAME) || true

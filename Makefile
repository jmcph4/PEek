PROJ_NAME = PEek
SRC_DIR = src
BIN_DIR = bin
CC = gcc

$(PROJ_NAME):
	$(CC) -o $(BIN_DIR)/$(PROJ_NAME) $(SRC_DIR)/*.c -Wall -Wextra -Wshadow -pedantic-errors -std=c11 -g

.PHONY: clean

clean:
	rm $(BIN_DIR)/$(PROJ_NAME) -r

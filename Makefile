SDIR=/src
IDIR =/include
CC=gcc
CFLAGS=-I$(IDIR)
BDIR=/bin
_DEPS = headers.h codes.h utils.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))
_OBJ = main.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(BDIR)/%.o: $(SDIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(BDIR)/PEek: $(OBJ)
	gcc -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(BDIR)/*.o *~ core $(INCDIR)/*~
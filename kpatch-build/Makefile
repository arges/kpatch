include ../Makefile.inc

CFLAGS  += -I../kmod/patch -Iinsn -Wall -g -Werror
LDFLAGS = -lelf

TARGETS = create-diff-object create-livepatch-object
OBJS = kpatch-elf.o lookup.o insn/insn.o insn/inat.o
SOURCES = create-diff-object.c create-livepatch-object.c kpatch-elf.c lookup.c insn/insn.c insn/inat.c

all: $(TARGETS)

-include $(SOURCES:.c=.d)

%.o : %.c
	$(CC) -MMD -MP $(CFLAGS) -c -o $@ $<

create-diff-object: create-diff-object.o $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

create-livepatch-object: create-livepatch-object.o $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

install: all
	$(INSTALL) -d $(LIBEXECDIR)
	$(INSTALL) $(TARGETS) kpatch-gcc $(LIBEXECDIR)
	$(INSTALL) -d $(BINDIR)
	$(INSTALL) kpatch-build $(BINDIR)

uninstall:
	$(RM) -R $(LIBEXECDIR)
	$(RM) $(BINDIR)/kpatch-build

clean:
	$(RM) $(TARGETS) $(OBJS) *.d insn/*.d

CC=cl /nologo
LINK=link
LIB_DIR=lib
LINK_FLAGS=/MACHINE:X86
SOURCES=depcheck2csv.c
CFLAGS=
OBJECTS=$(SOURCES:.c=.obj)
LIBS=kernel32.lib shell32.lib user32.lib libxml2.lib legacy_stdio_definitions.lib shlwapi.lib
INCLUDE_DIR=include

all:
	$(CC) $(CFLAGS) /I $(INCLUDE_DIR) $(SOURCES) /link $(LINK_FLAGS) /LIBPATH:$(LIB_DIR) $(LIBS)
clean:
	del $(OBJECTS) depcheck2csv.exe

CC=g++

CFLAGS		= -Wall -g3 -gdwarf-2 -O0 -fmessage-length=0 -fpermissive
SOURCES_CAP =$(shell ls ./*.c )

OBJS_CAP =$(SOURCES_CAP:.c=.o)
OBJS_READ =$(SOURCES_READ:.c=.o)

EXEC_CAP =sniffex

LIBS_CAP =-lpcap  

all: Cap
	@echo 
	@echo "     **   Completed sucessfully  **" 
	@echo

Cap: $(SOURCES_CAP) $(EXEC_CAP)


%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "--------------------------------------"
	
$(EXEC_CAP): $(OBJS_CAP)
	$(CC) $(CFLAGS) $(OBJS_CAP) $(LIBS_CAP) -o $@


clean: 

	rm -f *~ *.o;
	
	rm -f $(EXEC_CAP)

	@echo

	@echo " ** To recompile, please type \"make\" **"

	@echo

.PHONY: all polycommit evss clean

all: polycommit evss

polycommit:
	make -C polycommit

evss:
	make -C evss
	
clean: 
	make -C polycommit clean
	make -C evss clean


.PHONY: all proto polycommit evss clean

all: proto polycommit evss

proto:
	make -C proto

polycommit:
	make -C polycommit

evss:
	make -C evss
	
clean: 
	make -C polycommit clean
	make -C evss clean


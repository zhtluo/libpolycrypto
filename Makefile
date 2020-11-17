.PHONY: all proto polycommit evss constantinople biaccumulator clean

all: proto polycommit evss constantinople biaccumulator

proto:
	make -C proto

polycommit:
	make -C polycommit

evss:
	make -C evss
	
constantinople:
	make -C constantinople

biaccumulator:
	make -C biaccumulator

clean: 
	make -C polycommit clean
	make -C evss clean
	make -C constantinople clean
	make -C biaccumulator clean


PKG:=github.com/dpw/ambergris

BUILD_ARGS:=-v $$PWD/build:/go \
	    -v $$PWD/build-in-container.sh:/build.sh \
	    --workdir=/go/src/$(PKG) \
	    -e GOPATH=/go

GOFILES:=$(shell find . -name '*.go')
SRC:=main.go interceptor coatl

.PHONY: image clean

image: .ambergris.uptodate

clean:
	rm -f ambergris .*.uptodate
	rm -rf build

.build.uptodate:
	docker build -t ambergris/build -f Dockerfile.build .
	touch $@

.ambergris.uptodate: Dockerfile ambergris
	docker build -t ambergris/server .
	touch $@

ambergris: .build.uptodate $(GOFILES) build-in-container.sh
	mkdir -p ./build/src/$(PKG)/
	cp -pR $(SRC) build/src/$(PKG)/
	docker run --rm $(BUILD_ARGS) ambergris/build sh /build.sh
	cp ./build/bin/ambergris $@

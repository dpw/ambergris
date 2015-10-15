PKG:=github.com/dpw/ambergris
GOFILES:=$(shell find . -name '*.go')
SRC:=main.go interceptor coatl

.PHONY: image clean

image: docker/.server.done

clean:
	rm -f ambergris docker/.*.done
	rm -rf build

.%.done: Dockerfile.%
	rm -rf build-container
	mkdir build-container
	cp -pr $^ build-container
	docker build -t ambergris/$(*F) -f build-container/$(<F) build-container
	rm -rf build-container
	touch $@

docker/.server.done: ambergris

ambergris: docker/.build.done docker/build-in-container.sh $(GOFILES)
	rm -rf build/src/$(PKG)
	mkdir -p build/src/$(PKG)
	cp -pr $(SRC) build/src/$(PKG)
	docker run -v $$PWD/build:/go \
	    -v $$PWD/docker/build-in-container.sh:/build.sh \
	    --workdir=/go/src/$(PKG) -e GOPATH=/go ambergris/build sh /build.sh
	cp build/bin/ambergris $@

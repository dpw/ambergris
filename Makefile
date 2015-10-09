.PHONY: image clean

BUILD_ARGS:=-v $$PWD/build:/go \
	    -v $$PWD:/go/src/github.com/dpw/ambergris \
	    -e CGO_ENABLED=0 \
	    --workdir=/go/src/github.com/dpw/ambergris \
	    -e GOPATH=/go

GOFILES:=$(shell find . -name '*.go')

image: .ambergris.uptodate

clean:
	rm -f ambergris a.out .ambergris.uptodate
	rm -rf build

.ambergris.uptodate: Dockerfile a.out
	docker build -t ambergris/server .
	touch $@

a.out: $(GOFILES)
	mkdir -p build
	docker run --rm $(BUILD_ARGS) \
		golang sh -c \
			'go get . && \
			 go build -o $@ .'

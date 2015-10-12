# Ambergris

* A iptables-based connection interceptor

* Works with plain docker, and with weave

* Just TCP forwarding for now

* Load balances over multiple instances, picking a random instance to
  forward each connection to.

## Building

```
go get github.com/dpw/ambergris
```

`make` will build a Docker container image `ambergris/server`

## Use with plain docker

```
S1=$(docker run -itd ubuntu nc -k -l 8000)
S2=$(docker run -itd ubuntu nc -k -l 8000)
docker run -d --privileged --net=host ambergris/server
echo 10.254.0.1:80 $(docker inspect -f '{{.NetworkSettings.IPAddress}}:8000' $S1 $S2) | nc -U /var/run/ambergris.sock
docker run --rm ubuntu sh -c 'seq 1 100 | while read n ; do echo $n | nc 10.254.0.1 80 ; done'
```

## Use with weave

```
weave launch-router
weave launch-proxy --rewrite-inspect
weave expose
eval $(weave env)
S1=$(docker run -itd ubuntu nc -k -l 8000)
S2=$(docker run -itd ubuntu nc -k -l 8000)
docker run -d --privileged --net=host ambergris/server
echo 10.254.0.1:80 $(docker inspect -f '{{.NetworkSettings.IPAddress}}:8000' $S1 $S2) | nc -U /var/run/ambergris.sock
docker run --rm ubuntu sh -c 'seq 1 100 | while read n ; do echo $n | nc 10.254.0.1 80 ; done'
```

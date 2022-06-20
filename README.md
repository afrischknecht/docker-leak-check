# docker-leak-check
Leak checker for Windows Docker daemons, used to find invalid images, and unreferenced layers.

Forked from https://github.com/olljanat/docker-leak-check and dusted off a little.

## Building
Currently only supports Windows properly. Provided that the system has a somewhat recent (1.18 or newer)
version of Go installed, the project can be simply built by:
```
go build -o docker-leak-check.exe app
```

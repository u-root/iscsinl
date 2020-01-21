module github.com/u-root/iscsinl

go 1.13

require (
	github.com/gostor/gotgt v0.1.0
	github.com/hugelgupf/p9 v0.0.0-20200121012303-e521180b4735
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/sirupsen/logrus v1.4.2 // indirect
	github.com/u-root/u-root v6.0.1-0.20200118052101-6bcd1cda5996+incompatible
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/sys v0.0.0-20200121082415-34d275377bf9
)

replace github.com/gostor/gotgt => github.com/hugelgupf/gotgt v0.0.0-20200122064518-6af024c2e322

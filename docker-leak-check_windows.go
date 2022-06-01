package main

import (
	"github.com/Microsoft/hcsshim"
)

func removeDiskLayer(location, foldername string) error {
	info := hcsshim.DriverInfo{
		HomeDir: location,
		Flavour: 0,
	}
	return hcsshim.DestroyLayer(info, foldername)
}

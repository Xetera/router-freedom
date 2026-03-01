package main

import "golang.org/x/sys/windows"

func checkPcapDeps() error {
	_, err := windows.LoadDLL("wpcap.dll")
	if err != nil {
		return errNpcapMissing
	}
	return nil
}

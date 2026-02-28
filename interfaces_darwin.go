package main

/*
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

static io_object_t find_service_by_bsd_name(const char *bsd_name) {
    CFMutableDictionaryRef matching = IOBSDNameMatching(0, 0, bsd_name);
    if (!matching) return 0;
    return IOServiceGetMatchingService(0, matching);
}

static int is_usb_interface(const char *bsd_name) {
    io_object_t service = find_service_by_bsd_name(bsd_name);
    if (!service) return 0;

    io_object_t entry = service;
    IOObjectRetain(entry);
    IOObjectRelease(service);

    while (entry) {
        io_name_t className;
        IOObjectGetClass(entry, className);
        if (strstr(className, "IOUSBHostDevice") ||
            strstr(className, "IOUSBDevice") ||
            strstr(className, "IOUSBHostInterface") ||
            strstr(className, "IOUSBInterface") ||
            strstr(className, "AppleUSB")) {
            IOObjectRelease(entry);
            return 1;
        }
        io_object_t parent;
        kern_return_t kr = IORegistryEntryGetParentEntry(entry, kIOServicePlane, &parent);
        IOObjectRelease(entry);
        if (kr != KERN_SUCCESS) break;
        entry = parent;
    }
    return 0;
}
*/
import "C"
import "unsafe"

func isUSBInterface(bsdName string) bool {
	cName := C.CString(bsdName)
	defer C.free(unsafe.Pointer(cName))
	return C.is_usb_interface(cName) != 0
}

func classifyInterfaces(ifaces []NetworkInterface) {
	for i := range ifaces {
		if isUSBInterface(ifaces[i].Name) {
			ifaces[i].TransportType = "usb"
		} else if len(ifaces[i].HardwareAddr) > 0 {
			ifaces[i].TransportType = "ethernet"
		}
	}
}

package utils

import (
	"runtime"
)

// IsLinux returns true if running on Linux
func IsLinux() bool {
    return runtime.GOOS == "linux"
}

// IsWindows returns true if running on Windows
func IsWindows() bool {
    return runtime.GOOS == "windows"
}

// IsMacOS returns true if running on macOS
func IsMacOS() bool {
    return runtime.GOOS == "darwin"
}
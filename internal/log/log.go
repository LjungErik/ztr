package log

import (
	"fmt"
	"io"
	"os"
)

type nopWriter struct{}

func (n *nopWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

var errorWriter io.Writer = os.Stderr
var debugWriter io.Writer = &nopWriter{}

func Errorf(format string, args ...interface{}) {
	fmt.Fprintf(errorWriter, "ERROR: "+format+"\n", args...)
}

func Debugf(format string, args ...interface{}) {
	fmt.Fprintf(debugWriter, "DEBUG: "+format+"\n", args...)
}

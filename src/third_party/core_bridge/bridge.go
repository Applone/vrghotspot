package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef void (*vrg_core_log_callback_t)(int level, const char* message, int message_len);

static inline void vrg_core_emit_log(vrg_core_log_callback_t callback, int level, const char* message, int message_len) {
	if (callback != NULL) {
		callback(level, message, message_len);
	}
}
*/
import "C"

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/metacubex/mihomo/config"
	C_ "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	mlog "github.com/metacubex/mihomo/log"
	logrus "github.com/sirupsen/logrus"
)

const (
	logLevelError = 1
	logLevelWarn  = 2
	logLevelInfo  = 3
	logLevelDebug = 4

	applyConfigTimeout = 30 * time.Second
)

// Mihomo keeps a single global instance (the `executor` package operates on
// process-global state), so there is at most one running tunnel. We hand a
// constant non-zero handle back to Rust for parity with the previous bridge
// and to keep the Rust lifecycle (start returns handle, stop consumes it)
// unchanged.
const runningHandle = 1

type applyResult struct {
	err error
}

var (
	instanceMu sync.Mutex
	running    bool
	initError  error

	logCallbackMu sync.RWMutex
	logCallback   C.vrg_core_log_callback_t
)

func init() {
	defer func() {
		if value := recover(); value != nil {
			msg := fmt.Sprintf("panic during core-bridge init: %v", value)
			initError = fmt.Errorf("%s", msg)
			_, _ = os.Stderr.WriteString(msg + "\n")
		}
	}()

	// Mihomo's log package (in its own init) points logrus at os.Stdout with a
	// `time="..." level=... msg="..."` TextFormatter, and every log call prints
	// there in addition to publishing on the observable channel. That direct
	// stdout write is a second, differently-formatted copy that interleaves with
	// the Rust tracing output. Our package imports mihomo/log, so our init runs
	// afterwards: redirect logrus to io.Discard so the observable channel (which
	// we forward to the Rust tracing pipeline) is the single source of truth.
	logrus.SetOutput(io.Discard)

	// Mihomo logs onto an unbuffered channel drained by an observable; each
	// subscriber gets a 200-slot buffer. Drain it continuously in the
	// background so a full buffer never stalls mihomo's logging (which would
	// otherwise block ApplyConfig).
	go pumpMihomoLogs()

	emitBridgeLog(logLevelInfo, fmt.Sprintf(
		"core-bridge initialized: go=%s, os=%s, arch=%s, mihomo=%s",
		runtime.Version(), runtime.GOOS, runtime.GOARCH, C_.Version,
	))
}

func pumpMihomoLogs() {
	defer func() {
		if value := recover(); value != nil {
			_, _ = os.Stderr.WriteString(fmt.Sprintf("panic in mihomo log pump: %v\n", value))
		}
	}()

	sub := mlog.Subscribe()
	for event := range sub {
		emitBridgeLog(mihomoLogLevel(event.LogLevel), "mihomo: "+strings.TrimSpace(event.Payload))
	}
}

func mihomoLogLevel(level mlog.LogLevel) int {
	switch level {
	case mlog.ERROR:
		return logLevelError
	case mlog.WARNING:
		return logLevelWarn
	case mlog.DEBUG:
		return logLevelDebug
	default:
		return logLevelInfo
	}
}

//export VrgCoreSetLogCallback
func VrgCoreSetLogCallback(callback C.vrg_core_log_callback_t) {
	logCallbackMu.Lock()
	logCallback = callback
	logCallbackMu.Unlock()
	emitBridgeLog(logLevelInfo, "Rust log callback registered with core-bridge")
}

//export VrgCoreSetHomeDir
func VrgCoreSetHomeDir(path *C.char, pathLen C.int, errBuf *C.char, errBufLen C.int) C.int {
	if path == nil || pathLen <= 0 {
		writeError(errBuf, errBufLen, "empty Mihomo home directory")
		return 1
	}

	homeDir := string(C.GoBytes(unsafe.Pointer(path), pathLen))
	emitBridgeLog(logLevelInfo, "configuring Mihomo home directory: "+homeDir)

	info, err := os.Stat(homeDir)
	if err != nil {
		msg := fmt.Sprintf("home directory does not exist: %s: %v", homeDir, err)
		emitBridgeLog(logLevelError, msg)
		writeError(errBuf, errBufLen, msg)
		return 1
	}
	if !info.IsDir() {
		msg := fmt.Sprintf("home directory is not a directory: %s", homeDir)
		emitBridgeLog(logLevelError, msg)
		writeError(errBuf, errBufLen, msg)
		return 1
	}

	// Mihomo resolves geodata (GeoIP.dat/GeoSite.dat/geoip.metadb) relative to
	// the home dir; the specific mode (.dat vs mmdb) is driven by the
	// `geodata-mode`/`geodata-loader` keys in the YAML config, not here.
	for _, name := range []string{"GeoIP.dat", "GeoSite.dat"} {
		datPath := homeDir + string(os.PathSeparator) + name
		if fi, err := os.Stat(datPath); err != nil {
			emitBridgeLog(logLevelWarn, fmt.Sprintf("geodata file missing: %s: %v", datPath, err))
		} else {
			emitBridgeLog(logLevelDebug, fmt.Sprintf("geodata file present: %s (%d bytes)", datPath, fi.Size()))
		}
	}

	C_.SetHomeDir(homeDir)
	emitBridgeLog(logLevelInfo, "Mihomo home directory configured successfully: "+homeDir)
	return 0
}

//export VrgCoreStartYAML
func VrgCoreStartYAML(configPtr *C.char, configLen C.int, errBuf *C.char, errBufLen C.int) (handle C.ulonglong) {
	defer func() {
		if value := recover(); value != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			message := fmt.Sprintf("panic starting embedded Mihomo: %v\ngoroutine stack:\n%s", value, string(buf[:n]))
			emitBridgeLog(logLevelError, message)
			writeError(errBuf, errBufLen, fmt.Sprintf("panic starting embedded Mihomo: %v", value))
			handle = 0
		}
	}()

	if initError != nil {
		msg := fmt.Sprintf("core-bridge init failed earlier: %v", initError)
		emitBridgeLog(logLevelError, msg)
		writeError(errBuf, errBufLen, msg)
		return 0
	}

	if configPtr == nil || configLen <= 0 {
		writeError(errBuf, errBufLen, "empty Mihomo configuration")
		return 0
	}

	configBytes := C.GoBytes(unsafe.Pointer(configPtr), configLen)

	instanceMu.Lock()
	defer instanceMu.Unlock()

	if running {
		// Tear the previous tunnel down before starting a new one so we never
		// stack two TUN adapters / route hijacks.
		emitBridgeLog(logLevelWarn, "an embedded Mihomo instance is already running; shutting it down before restart")
		shutdownLocked()
	}

	// Parse + validate first; this is where bad YAML or an invalid proxy
	// surfaces as an error we can return to Rust.
	cfg, err := executor.ParseWithBytes(configBytes)
	if err != nil {
		msg := fmt.Sprintf("failed to parse Mihomo configuration: %v", err)
		emitBridgeLog(logLevelError, msg)
		writeError(errBuf, errBufLen, err.Error())
		return 0
	}

	emitBridgeLog(logLevelInfo, fmt.Sprintf("applying Mihomo configuration (config size: %d bytes)", len(configBytes)))
	summarizeConfig(cfg)

	// executor.ApplyConfig is synchronous and returns nothing: it brings up
	// listeners/TUN/DNS and blocks until providers finish initial load. Guard
	// it with a timeout so a hang in TUN/Wintun init surfaces instead of
	// blocking the caller forever.
	resultCh := make(chan applyResult, 1)
	go func() {
		defer func() {
			if value := recover(); value != nil {
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				message := fmt.Sprintf("panic in executor.ApplyConfig: %v\ngoroutine stack:\n%s", value, string(buf[:n]))
				emitBridgeLog(logLevelError, message)
				resultCh <- applyResult{err: fmt.Errorf("panic in executor.ApplyConfig: %v", value)}
			}
		}()

		executor.ApplyConfig(cfg, true)
		resultCh <- applyResult{}
	}()

	select {
	case result := <-resultCh:
		if result.err != nil {
			writeError(errBuf, errBufLen, result.err.Error())
			return 0
		}
	case <-time.After(applyConfigTimeout):
		msg := fmt.Sprintf(
			"timed out after %s while applying Mihomo configuration; the core may be blocked in TUN/Wintun initialization or a network driver call",
			applyConfigTimeout,
		)
		emitBridgeLog(logLevelError, msg)
		writeError(errBuf, errBufLen, msg)
		return 0
	}

	running = true
	emitBridgeLog(logLevelInfo, "embedded Mihomo instance started successfully")
	return C.ulonglong(runningHandle)
}

func summarizeConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}
	proxyCount := len(cfg.Proxies)
	ruleCount := len(cfg.Rules)
	tunEnabled := false
	if cfg.General != nil {
		tunEnabled = cfg.General.Tun.Enable
	}
	emitBridgeLog(logLevelDebug, fmt.Sprintf(
		"  config summary: proxies=%d, rules=%d, tun_enabled=%v",
		proxyCount, ruleCount, tunEnabled,
	))
}

//export VrgCoreStop
func VrgCoreStop(handle C.ulonglong, errBuf *C.char, errBufLen C.int) (result C.int) {
	defer func() {
		if value := recover(); value != nil {
			message := fmt.Sprintf("panic stopping embedded Mihomo: %v", value)
			emitBridgeLog(logLevelError, message)
			writeError(errBuf, errBufLen, message)
			result = 1
		}
	}()

	instanceMu.Lock()
	defer instanceMu.Unlock()

	if !running {
		emitBridgeLog(logLevelWarn, "stop requested while no embedded Mihomo instance is running")
		return 0
	}

	emitBridgeLog(logLevelInfo, "stopping embedded Mihomo instance")
	shutdownLocked()
	emitBridgeLog(logLevelInfo, "embedded Mihomo instance stopped")
	return 0
}

// shutdownLocked tears the running tunnel down. It must be called with
// instanceMu held. executor.Shutdown() alone does not drop the TUN interface,
// so we first apply a minimal TUN-disabled config to close the adapter and
// restore the default route, then run the full shutdown.
func shutdownLocked() {
	defer func() {
		if value := recover(); value != nil {
			emitBridgeLog(logLevelError, fmt.Sprintf("panic during Mihomo shutdown: %v", value))
		}
	}()

	if cfg, err := executor.ParseWithBytes([]byte(tunDisabledConfig)); err != nil {
		emitBridgeLog(logLevelWarn, "failed to parse TUN-disabled teardown config: "+err.Error())
	} else {
		executor.ApplyConfig(cfg, true)
	}

	executor.Shutdown()
	running = false
}

// A minimal config with TUN disabled and no proxies. Applying it closes the
// TUN adapter and removes the hijacked default route before full shutdown.
const tunDisabledConfig = `mode: direct
log-level: warning
tun:
  enable: false
`

//export VrgCoreVersion
func VrgCoreVersion(buf *C.char, bufLen C.int) {
	// Write into a caller-provided buffer (same pattern as the error buffers)
	// so there is no CString for the caller to free and no memory to leak.
	writeError(buf, bufLen, C_.Version)
}

func emitBridgeLog(level int, message string) {
	message = strings.TrimSpace(message)
	if message == "" {
		return
	}

	logCallbackMu.RLock()
	callback := logCallback
	logCallbackMu.RUnlock()

	if callback == nil {
		_, _ = os.Stderr.WriteString(message + "\n")
		return
	}

	cMessage := C.CString(message)
	defer C.free(unsafe.Pointer(cMessage))
	C.vrg_core_emit_log(callback, C.int(level), cMessage, C.int(len(message)))
}

func writeError(errBuf *C.char, errBufLen C.int, message string) {
	if errBuf == nil || errBufLen <= 0 {
		return
	}

	bytes := append([]byte(message), 0)
	max := int(errBufLen)
	if len(bytes) > max {
		bytes = bytes[:max]
		bytes[max-1] = 0
	}

	for index, value := range bytes {
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(errBuf)) + uintptr(index))) = value
	}
}

func main() {}

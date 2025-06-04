package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/time/rate"
)

// Config represents the complete application configuration
type Config struct {
	Server       ServerConfig       `json:"server"`
	Syslog       SyslogConfig       `json:"syslog"`
	CEF          CEFConfig          `json:"cef"`
	FieldMapping FieldMappingConfig `json:"field_mapping"`
	Security     SecurityConfig     `json:"security"`
	Web          WebConfig          `json:"web"`
	Logging      LoggingConfig      `json:"logging"`
	Parsing      ParsingConfig      `json:"parsing"`
	Protection   ProtectionConfig   `json:"protection"`
}

// ProtectionConfig holds resource protection settings
type ProtectionConfig struct {
	MaxMemoryMB          int    `json:"max_memory_mb"`
	MaxConcurrentReqs    int    `json:"max_concurrent_requests"`
	RequestTimeout       string `json:"request_timeout"`
	MaxJSONDepth         int    `json:"max_json_depth"`
	MaxFieldCount        int    `json:"max_field_count"`
	MaxFieldValueLength  int    `json:"max_field_value_length"`
	EnablePanicRecovery  bool   `json:"enable_panic_recovery"`
	MemoryCheckInterval  string `json:"memory_check_interval"`
	EnableCircuitBreaker bool   `json:"enable_circuit_breaker"`
	CircuitBreakerLimit  int    `json:"circuit_breaker_limit"`
}

// ParsingConfig holds parsing configuration for different input formats
type ParsingConfig struct {
	DefaultEventType     string            `json:"default_event_type"`
	DefaultSeverity      string            `json:"default_severity"`
	SyslogRegex          string            `json:"syslog_regex"`
	KeyValueSeparators   []string          `json:"key_value_separators"`
	FieldSeparators      []string          `json:"field_separators"`
	TimestampFormats     []string          `json:"timestamp_formats"`
	FallbackFieldMapping map[string]string `json:"fallback_field_mapping"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	LocalOnly    bool   `json:"local_only"`
	LocalLogFile string `json:"local_log_file"`
	LogLevel     string `json:"log_level"`
}

// WebConfig holds web interface configuration
type WebConfig struct {
	IndexPage   string `json:"index_page"`
	StaticDir   string `json:"static_dir"`
	EnableIndex bool   `json:"enable_index"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	ListenAddr        string `json:"listen_addr"`
	TLSCertFile       string `json:"tls_cert_file"`
	TLSKeyFile        string `json:"tls_key_file"`
	ReadTimeout       string `json:"read_timeout"`
	WriteTimeout      string `json:"write_timeout"`
	IdleTimeout       string `json:"idle_timeout"`
	ReadHeaderTimeout string `json:"read_header_timeout"`
	MaxBodySize       int64  `json:"max_body_size"`
	MaxHeaderBytes    int    `json:"max_header_bytes"`
	ShutdownTimeout   string `json:"shutdown_timeout"`
	TLSMinVersion     string `json:"tls_min_version"`
	EnableHTTP2       bool   `json:"enable_http2"`
}

// SyslogConfig holds syslog configuration
type SyslogConfig struct {
	Address         string `json:"address"`
	Protocol        string `json:"protocol"`
	Facility        string `json:"facility"`
	PoolSize        int    `json:"pool_size"`
	Tag             string `json:"tag"`
	ConnectTimeout  string `json:"connect_timeout"`
	WriteTimeout    string `json:"write_timeout"`
	RetryInterval   string `json:"retry_interval"`
	MaxRetries      int    `json:"max_retries"`
	TimestampFormat string `json:"timestamp_format"`
	Hostname        string `json:"hostname"`
}

// CEFConfig holds CEF format configuration
type CEFConfig struct {
	Version       string            `json:"version"`
	DeviceVendor  string            `json:"device_vendor"`
	DeviceProduct string            `json:"device_product"`
	DeviceVersion string            `json:"device_version"`
	Extensions    map[string]string `json:"extensions"`
}

// FieldMappingConfig defines how incoming fields map to CEF fields
type FieldMappingConfig struct {
	TimestampField   []string            `json:"timestamp_field"`
	SeverityField    []string            `json:"severity_field"`
	EventTypeField   []string            `json:"event_type_field"`
	SourceField      []string            `json:"source_field"`
	DestinationField []string            `json:"destination_field"`
	MessageField     []string            `json:"message_field"`
	SignatureField   []string            `json:"signature_field"`
	CEFExtensions    []CEFExtensionField `json:"cef_extensions"`
	SeverityMap      map[string]string   `json:"severity_map"`
	ConditionalMaps  []ConditionalMapping `json:"conditional_maps"`
}

// CEFExtensionField defines an ordered CEF extension field
type CEFExtensionField struct {
	Name    string       `json:"name"`
	Mapping FieldMapping `json:"mapping"`
}

// FieldMapping defines how to extract and map a field
type FieldMapping struct {
	Sources    []string         `json:"sources"`
	Transform  string           `json:"transform,omitempty"`
	Default    string           `json:"default,omitempty"`
	Conditions []FieldCondition `json:"conditions,omitempty"`
}

// FieldCondition allows conditional field mapping
type FieldCondition struct {
	Field    string `json:"field"`
	Value    string `json:"value"`
	Operator string `json:"operator"` // equals, contains, starts_with, regex
	MapTo    string `json:"map_to"`
}

// ConditionalMapping allows different CEF configurations based on event properties
type ConditionalMapping struct {
	Condition    FieldCondition `json:"condition"`
	CEFOverrides CEFConfig      `json:"cef_overrides"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	EnableAuth      bool     `json:"enable_auth"`
	APIKeys         []string `json:"api_keys"`
	RateLimit       int      `json:"rate_limit"`
	RateBurst       int      `json:"rate_burst"`
	RateLimitWindow string   `json:"rate_limit_window"`
	AllowedIPs      []string `json:"allowed_ips,omitempty"`
	BlockedIPs      []string `json:"blocked_ips,omitempty"`
	RequireHTTPS    bool     `json:"require_https"`
	CSRFProtection  bool     `json:"csrf_protection"`
	CORSEnabled     bool     `json:"cors_enabled"`
	CORSOrigins     []string `json:"cors_origins"`
}

// CircuitBreaker implements a simple circuit breaker pattern
type CircuitBreaker struct {
	mu           sync.RWMutex
	failures     int64
	lastFailTime time.Time
	state        int32 // 0 = closed, 1 = open, 2 = half-open
	threshold    int
	timeout      time.Duration
}

func NewCircuitBreaker(threshold int) *CircuitBreaker {
	return &CircuitBreaker{
		threshold: threshold,
		timeout:   30 * time.Second,
	}
}

func (cb *CircuitBreaker) Call(fn func() error) error {
	if !cb.Allow() {
		return fmt.Errorf("circuit breaker is open")
	}

	err := fn()
	if err != nil {
		cb.RecordFailure()
		return err
	}

	cb.RecordSuccess()
	return nil
}

func (cb *CircuitBreaker) Allow() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	state := atomic.LoadInt32(&cb.state)
	if state == 0 { // closed
		return true
	}

	if state == 1 { // open
		if time.Since(cb.lastFailTime) > cb.timeout {
			atomic.StoreInt32(&cb.state, 2) // half-open
			return true
		}
		return false
	}

	// half-open
	return true
}

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	atomic.StoreInt64(&cb.failures, 0)
	atomic.StoreInt32(&cb.state, 0) // closed
}

func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	failures := atomic.AddInt64(&cb.failures, 1)
	cb.lastFailTime = time.Now()
	if int(failures) >= cb.threshold {
		atomic.StoreInt32(&cb.state, 1) // open
	}
}

// SyslogForwarder handles syslog connections with connection pooling
type SyslogForwarder struct {
	mu         sync.RWMutex
	conns      []net.Conn
	config     *SyslogConfig
	facility   int
	roundRobin int
	hostname   string
}

// EventProcessor handles the main processing logic
type EventProcessor struct {
	syslogForwarder *SyslogForwarder
	limiter         *rate.Limiter
	config          *Config
	allowedIPs      map[string]bool
	allowedNetworks []*net.IPNet
	blockedIPs      map[string]bool
	blockedNetworks []*net.IPNet
	localLogger     *log.Logger
	localLogFile    *os.File
	syslogRegex     *regexp.Regexp
	concurrentReqs  int64
	circuitBreaker  *CircuitBreaker
	lastMemoryCheck time.Time
	memoryMutex     sync.RWMutex
}

// ParsedMessage represents a parsed message in our internal format
type ParsedMessage struct {
	Data         map[string]interface{} `json:"data"`
	OriginalText string                 `json:"original_text"`
	Format       string                 `json:"format"`
}

// ProtectedReader wraps io.Reader with size and timeout protection
type ProtectedReader struct {
	reader    io.Reader
	maxSize   int64
	bytesRead int64
	timeout   time.Duration
	deadline  time.Time
}

func NewProtectedReader(r io.Reader, maxSize int64, timeout time.Duration) *ProtectedReader {
	return &ProtectedReader{
		reader:   r,
		maxSize:  maxSize,
		timeout:  timeout,
		deadline: time.Now().Add(timeout),
	}
}

func (pr *ProtectedReader) Read(p []byte) (int, error) {
	if time.Now().After(pr.deadline) {
		return 0, fmt.Errorf("read timeout exceeded")
	}

	if pr.bytesRead >= pr.maxSize {
		return 0, fmt.Errorf("maximum read size exceeded: %d bytes", pr.maxSize)
	}

	remainingBytes := pr.maxSize - pr.bytesRead
	if int64(len(p)) > remainingBytes {
		p = p[:remainingBytes]
	}

	n, err := pr.reader.Read(p)
	pr.bytesRead += int64(n)
	return n, err
}

// SafeJSONDecoder provides protected JSON decoding
func SafeJSONDecoder(data []byte, maxDepth int, maxFields int) (map[string]interface{}, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty JSON data")
	}

	decoder := json.NewDecoder(strings.NewReader(string(data)))

	var result map[string]interface{}
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("JSON decode error: %w", err)
	}

	// Check depth and field count
	if err := validateJSONStructure(result, maxDepth, maxFields, 0); err != nil {
		return nil, err
	}

	return result, nil
}

func validateJSONStructure(data interface{}, maxDepth, maxFields, currentDepth int) error {
	if currentDepth > maxDepth {
		return fmt.Errorf("JSON depth exceeds maximum: %d", maxDepth)
	}

	switch v := data.(type) {
	case map[string]interface{}:
		if len(v) > maxFields {
			return fmt.Errorf("JSON field count exceeds maximum: %d", maxFields)
		}
		for _, value := range v {
			if err := validateJSONStructure(value, maxDepth, maxFields, currentDepth+1); err != nil {
				return err
			}
		}
	case []interface{}:
		if len(v) > maxFields {
			return fmt.Errorf("JSON array size exceeds maximum: %d", maxFields)
		}
		for _, item := range v {
			if err := validateJSONStructure(item, maxDepth, maxFields, currentDepth+1); err != nil {
				return err
			}
		}
	case string:
		// Check string length
		if len(v) > 10000 { // Max 10KB per string field
			return fmt.Errorf("JSON string field too long: %d characters", len(v))
		}
	}

	return nil
}

// CheckMemoryUsage monitors memory usage
func (ep *EventProcessor) CheckMemoryUsage() bool {
	ep.memoryMutex.RLock()
	defer ep.memoryMutex.RUnlock()

	if ep.config.Protection.MaxMemoryMB <= 0 {
		return true // No memory limit
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	usedMB := int(m.Alloc / 1024 / 1024)
	maxMB := ep.config.Protection.MaxMemoryMB

	if usedMB > maxMB {
		log.Printf("Memory usage exceeded: %dMB > %dMB", usedMB, maxMB)
		return false
	}

	return true
}

// StartMemoryMonitor starts a goroutine to monitor memory usage
func (ep *EventProcessor) StartMemoryMonitor() {
	if ep.config.Protection.MaxMemoryMB <= 0 {
		return
	}

	interval := parseDuration(ep.config.Protection.MemoryCheckInterval, 30*time.Second)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			if !ep.CheckMemoryUsage() {
				// Force garbage collection
				runtime.GC()
				runtime.GC() // Call twice for more aggressive cleanup
			}
		}
	}()
}

// NewSyslogForwarder creates a new syslog forwarder with connection pooling
func NewSyslogForwarder(config *SyslogConfig) (*SyslogForwarder, error) {
	facility := parseSyslogFacility(config.Facility)

	hostname := config.Hostname
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "localhost"
		}
	}

	sf := &SyslogForwarder{
		config:   config,
		facility: facility,
		conns:    make([]net.Conn, 0, config.PoolSize),
		hostname: hostname,
	}

	// Only create connections if we have an address
	if config.Address != "" {
		// Create connection pool
		for i := 0; i < config.PoolSize; i++ {
			conn, err := net.Dial(config.Protocol, config.Address)
			if err != nil {
				sf.Close()
				return nil, fmt.Errorf("failed to create syslog connection %d: %w", i, err)
			}
			sf.conns = append(sf.conns, conn)
		}
	}

	return sf, nil
}

// Forward sends a message to syslog using round-robin connection selection
func (sf *SyslogForwarder) Forward(priority int, message string) error {
	sf.mu.Lock()
	if len(sf.conns) == 0 {
		sf.mu.Unlock()
		return fmt.Errorf("no available syslog connections")
	}

	conn := sf.conns[sf.roundRobin%len(sf.conns)]
	sf.roundRobin++
	sf.mu.Unlock()

	// Calculate priority value (facility * 8 + severity)
	priorityValue := sf.facility*8 + priority

	// Format timestamp in syslog format
	timestampFormat := sf.config.TimestampFormat
	if timestampFormat == "" {
		timestampFormat = "Jan _2 15:04:05"
	}
	timestamp := time.Now().Format(timestampFormat)

	// Get tag
	tag := sf.config.Tag
	if tag == "" {
		tag = "event-forwarder"
	}

	// Format as RFC3164 syslog message with PID
	syslogMessage := fmt.Sprintf("<%d>%s %s %s[%d]: %s\n",
		priorityValue, timestamp, sf.hostname, tag, os.Getpid(), message)

	_, err := conn.Write([]byte(syslogMessage))
	return err
}

// Close closes all syslog connections
func (sf *SyslogForwarder) Close() {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	for _, conn := range sf.conns {
		if conn != nil {
			conn.Close()
		}
	}
	sf.conns = nil
}

// ParseMessage attempts to parse any message format into our internal structure
func (ep *EventProcessor) ParseMessage(rawMessage string) (*ParsedMessage, error) {
	// Validate message size
	maxLen := ep.config.Protection.MaxFieldValueLength
	if maxLen > 0 && len(rawMessage) > maxLen {
		return nil, fmt.Errorf("message too long: %d > %d", len(rawMessage), maxLen)
	}

	rawMessage = strings.TrimSpace(rawMessage)
	if rawMessage == "" {
		return nil, fmt.Errorf("empty message")
	}

	parsed := &ParsedMessage{
		Data:         make(map[string]interface{}),
		OriginalText: rawMessage,
		Format:       "unknown",
	}

	// Try JSON first
	if strings.HasPrefix(rawMessage, "{") || strings.HasPrefix(rawMessage, "[") {
		maxDepth := ep.config.Protection.MaxJSONDepth
		if maxDepth == 0 {
			maxDepth = 10
		}
		maxFields := ep.config.Protection.MaxFieldCount
		if maxFields == 0 {
			maxFields = 100
		}

		if jsonData, err := SafeJSONDecoder([]byte(rawMessage), maxDepth, maxFields); err == nil {
			parsed.Format = "json"
			parsed.Data = jsonData
			return parsed, nil
		}
	}

	// Try syslog format
	if ep.syslogRegex != nil {
		if matches := ep.syslogRegex.FindStringSubmatch(rawMessage); matches != nil {
			parsed.Format = "syslog"
			return ep.parseSyslogMessage(rawMessage, matches, parsed)
		}
	}

	// Try key-value pairs
	if kvData := ep.parseKeyValuePairs(rawMessage); len(kvData) > 1 {
		parsed.Format = "key-value"
		parsed.Data = kvData
		return parsed, nil
	}

	// Try CEF format
	if strings.HasPrefix(rawMessage, "CEF:") {
		parsed.Format = "cef"
		return ep.parseCEFMessage(rawMessage, parsed)
	}

	// Try CSV/delimited format
	if csvData := ep.parseDelimitedMessage(rawMessage); len(csvData) > 1 {
		parsed.Format = "delimited"
		parsed.Data = csvData
		return parsed, nil
	}

	// Fallback to plain text
	parsed.Format = "plaintext"
	parsed.Data = ep.parsePlainTextMessage(rawMessage)

	return parsed, nil
}

// parseSyslogMessage parses a syslog format message
func (ep *EventProcessor) parseSyslogMessage(rawMessage string, matches []string, parsed *ParsedMessage) (*ParsedMessage, error) {
	// Default syslog regex groups: timestamp, hostname, tag, pid, message
	if len(matches) >= 5 {
		parsed.Data["timestamp"] = matches[1]
		parsed.Data["hostname"] = matches[2]
		parsed.Data["program"] = matches[3]
		if matches[4] != "" {
			parsed.Data["pid"] = matches[4]
		}
		parsed.Data["message"] = matches[5]
		parsed.Data["event_type"] = "syslog"
		parsed.Data["severity"] = "info"
	}
	return parsed, nil
}

// parseKeyValuePairs attempts to parse key=value pairs
func (ep *EventProcessor) parseKeyValuePairs(message string) map[string]interface{} {
	data := make(map[string]interface{})

	separators := ep.config.Parsing.KeyValueSeparators
	if len(separators) == 0 {
		separators = []string{"=", ":"}
	}

	fieldSeparators := ep.config.Parsing.FieldSeparators
	if len(fieldSeparators) == 0 {
		fieldSeparators = []string{" ", ",", ";", "\t"}
	}

	maxFields := ep.config.Protection.MaxFieldCount
	if maxFields == 0 {
		maxFields = 100
	}

	maxValueLen := ep.config.Protection.MaxFieldValueLength
	if maxValueLen == 0 {
		maxValueLen = 10000
	}

	// Try different field separators
	for _, fieldSep := range fieldSeparators {
		fields := strings.Split(message, fieldSep)
		if len(fields) < 2 || len(fields) > maxFields {
			continue
		}

		tempData := make(map[string]interface{})
		validPairs := 0

		for _, field := range fields {
			field = strings.TrimSpace(field)
			if field == "" {
				continue
			}

			// Try different key-value separators
			for _, kvSep := range separators {
				if strings.Contains(field, kvSep) {
					parts := strings.SplitN(field, kvSep, 2)
					if len(parts) == 2 {
						key := strings.TrimSpace(parts[0])
						value := strings.TrimSpace(parts[1])
						// Remove quotes if present
						value = strings.Trim(value, "\"'")

						// Validate lengths
						if len(key) > 100 || len(value) > maxValueLen {
							continue
						}

						if key != "" {
							tempData[key] = value
							validPairs++
						}
						break
					}
				}
			}
		}

		// If we found enough valid pairs, use this data
		if validPairs >= 2 {
			data = tempData
			break
		}
	}

	return data
}

// parseCEFMessage parses a CEF format message
func (ep *EventProcessor) parseCEFMessage(message string, parsed *ParsedMessage) (*ParsedMessage, error) {
	// CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
	parts := strings.SplitN(message, "|", 8)
	if len(parts) < 7 {
		return parsed, fmt.Errorf("invalid CEF format")
	}

	parsed.Data["cef_version"] = strings.TrimPrefix(parts[0], "CEF:")
	parsed.Data["device_vendor"] = parts[1]
	parsed.Data["device_product"] = parts[2]
	parsed.Data["device_version"] = parts[3]
	parsed.Data["signature"] = parts[4]
	parsed.Data["event_type"] = parts[5]
	parsed.Data["severity"] = parts[6]

	// Parse extensions if present
	if len(parts) == 8 && parts[7] != "" {
		extensions := ep.parseKeyValuePairs(parts[7])
		for key, value := range extensions {
			parsed.Data[key] = value
		}
	}

	return parsed, nil
}

// parseDelimitedMessage attempts to parse CSV or other delimited formats
func (ep *EventProcessor) parseDelimitedMessage(message string) map[string]interface{} {
	data := make(map[string]interface{})

	maxFields := ep.config.Protection.MaxFieldCount
	if maxFields == 0 {
		maxFields = 100
	}

	// Try different delimiters
	delimiters := []string{",", "\t", "|", ";"}

	for _, delimiter := range delimiters {
		if strings.Contains(message, delimiter) {
			fields := strings.Split(message, delimiter)
			if len(fields) >= 2 && len(fields) <= maxFields {
				// Create generic field names
				for i, field := range fields {
					field = strings.TrimSpace(field)
					field = strings.Trim(field, "\"'") // Remove quotes
					if field != "" && len(field) <= 1000 {
						data[fmt.Sprintf("field_%d", i+1)] = field
					}
				}
				// If we have enough fields, consider this successful
				if len(data) >= 2 {
					data["event_type"] = "delimited"
					data["message"] = message
					break
				}
			}
		}
	}

	return data
}

// parsePlainTextMessage handles plain text messages
func (ep *EventProcessor) parsePlainTextMessage(message string) map[string]interface{} {
	data := make(map[string]interface{})

	// Set defaults
	data["message"] = message
	data["event_type"] = ep.config.Parsing.DefaultEventType
	if data["event_type"] == "" {
		data["event_type"] = "plaintext"
	}

	data["severity"] = ep.config.Parsing.DefaultSeverity
	if data["severity"] == "" {
		data["severity"] = "info"
	}

	data["timestamp"] = time.Now().Format(time.RFC3339)

	// Apply fallback field mapping if configured
	for pattern, fieldName := range ep.config.Parsing.FallbackFieldMapping {
		if strings.Contains(strings.ToLower(message), strings.ToLower(pattern)) {
			data[fieldName] = pattern
		}
	}

	return data
}

// ExtractFieldValue extracts a field value from event data using the configured sources
func ExtractFieldValue(eventData map[string]interface{}, sources []string) string {
	for _, source := range sources {
		if value := getNestedValue(eventData, source); value != "" {
			return value
		}
	}
	return ""
}

// getNestedValue extracts nested values using dot notation (e.g., "details.user.name")
func getNestedValue(data map[string]interface{}, path string) string {
	parts := strings.Split(path, ".")
	current := data

	for i, part := range parts {
		if i == len(parts)-1 {
			if val, exists := current[part]; exists {
				return fmt.Sprintf("%v", val)
			}
		} else {
			if val, exists := current[part]; exists {
				if nested, ok := val.(map[string]interface{}); ok {
					current = nested
				} else {
					return ""
				}
			} else {
				return ""
			}
		}
	}
	return ""
}

// parseTimestamp attempts to parse a timestamp from various formats
func parseTimestamp(value string) (time.Time, error) {
	// Common timestamp formats to try
	formats := []string{
		time.RFC3339,                // 2006-01-02T15:04:05Z07:00
		time.RFC3339Nano,            // 2006-01-02T15:04:05.999999999Z07:00
		"2006-01-02T15:04:05",       // ISO 8601 without timezone
		"2006-01-02 15:04:05",       // Common database format
		"Jan  2 15:04:05",           // Syslog format
		"Jan _2 15:04:05",           // Syslog format with single space
		"2006-01-02",                // Date only
		"15:04:05",                  // Time only (will use today's date)
		"1136239445",                // Unix timestamp (as string)
		"Mon Jan _2 15:04:05 2006",  // Full syslog format
		"Jan _2 15:04:05 2006",      // Syslog without day
	}

	for _, format := range formats {
		if t, err := time.Parse(format, value); err == nil {
			return t, nil
		}
	}

	// Try parsing as Unix timestamp (integer)
	if unixTime, err := strconv.ParseInt(value, 10, 64); err == nil {
		// Handle both seconds and milliseconds
		if unixTime > 1e12 { // Milliseconds
			return time.Unix(unixTime/1000, (unixTime%1000)*1e6), nil
		} else { // Seconds
			return time.Unix(unixTime, 0), nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse timestamp: %s", value)
}

// ApplyTransform applies transformation to field values
func ApplyTransform(value, transform string) string {
	switch transform {
	case "lowercase":
		return strings.ToLower(value)
	case "uppercase":
		return strings.ToUpper(value)
	case "trim":
		return strings.TrimSpace(value)
	case "timestamp_unix":
		if t, err := parseTimestamp(value); err == nil {
			return strconv.FormatInt(t.Unix(), 10)
		}
		return value
	case "timestamp_unix_ms":
		if t, err := parseTimestamp(value); err == nil {
			return strconv.FormatInt(t.UnixMilli(), 10)
		}
		return value
	case "timestamp_syslog":
		if t, err := parseTimestamp(value); err == nil {
			return t.Format("Jan _2 15:04:05")
		}
		return value
	case "timestamp_iso":
		if t, err := parseTimestamp(value); err == nil {
			return t.Format(time.RFC3339)
		}
		return value
	default:
		return value
	}
}

// EvaluateCondition evaluates a field condition
func EvaluateCondition(eventData map[string]interface{}, condition FieldCondition) bool {
	fieldValue := getNestedValue(eventData, condition.Field)

	switch condition.Operator {
	case "equals":
		return fieldValue == condition.Value
	case "contains":
		return strings.Contains(fieldValue, condition.Value)
	case "starts_with":
		return strings.HasPrefix(fieldValue, condition.Value)
	case "ends_with":
		return strings.HasSuffix(fieldValue, condition.Value)
	default:
		return fieldValue == condition.Value
	}
}

// ConvertToCEF converts event data to CEF format using configuration
func (ep *EventProcessor) ConvertToCEF(eventData map[string]interface{}) string {
	config := ep.config
	mapping := config.FieldMapping
	cefConfig := config.CEF

	// Check for conditional mappings
	for _, conditionalMap := range mapping.ConditionalMaps {
		if EvaluateCondition(eventData, conditionalMap.Condition) {
			// Apply CEF overrides
			if conditionalMap.CEFOverrides.DeviceVendor != "" {
				cefConfig.DeviceVendor = conditionalMap.CEFOverrides.DeviceVendor
			}
			if conditionalMap.CEFOverrides.DeviceProduct != "" {
				cefConfig.DeviceProduct = conditionalMap.CEFOverrides.DeviceProduct
			}
			if conditionalMap.CEFOverrides.DeviceVersion != "" {
				cefConfig.DeviceVersion = conditionalMap.CEFOverrides.DeviceVersion
			}
			break
		}
	}

	// Extract core CEF fields
	timestamp := ExtractFieldValue(eventData, mapping.TimestampField)
	severity := ExtractFieldValue(eventData, mapping.SeverityField)
	eventType := ExtractFieldValue(eventData, mapping.EventTypeField)
	source := ExtractFieldValue(eventData, mapping.SourceField)
	destination := ExtractFieldValue(eventData, mapping.DestinationField)
	message := ExtractFieldValue(eventData, mapping.MessageField)
	signature := ExtractFieldValue(eventData, mapping.SignatureField)

	// Map severity
	if mappedSeverity, exists := mapping.SeverityMap[strings.ToLower(severity)]; exists {
		severity = mappedSeverity
	} else if severity == "" {
		severity = "5" // Default medium severity
	}

	// Generate signature ID if not provided
	if signature == "" {
		signature = generateSignatureID(eventType)
	}

	// Build CEF header
	header := fmt.Sprintf("CEF:%s|%s|%s|%s|%s|%s|%s",
		cefConfig.Version,
		escapeCEFField(cefConfig.DeviceVendor),
		escapeCEFField(cefConfig.DeviceProduct),
		escapeCEFField(cefConfig.DeviceVersion),
		escapeCEFField(signature),
		escapeCEFField(eventType),
		escapeCEFField(severity),
	)

	// Build extensions in the exact order specified in config
	var extensionPairs []string

	// Track which fields we've already processed
	processedFields := make(map[string]bool)

	// Track source fields that have been mapped to avoid duplicates
	mappedSources := make(map[string]bool)

	// Add core field sources to mapped sources
	for _, field := range mapping.TimestampField {
		mappedSources[field] = true
	}
	for _, field := range mapping.SeverityField {
		mappedSources[field] = true
	}
	for _, field := range mapping.EventTypeField {
		mappedSources[field] = true
	}
	for _, field := range mapping.SourceField {
		mappedSources[field] = true
	}
	for _, field := range mapping.DestinationField {
		mappedSources[field] = true
	}
	for _, field := range mapping.MessageField {
		mappedSources[field] = true
	}
	for _, field := range mapping.SignatureField {
		mappedSources[field] = true
	}

	// Process CEF extensions in the order they appear in the config
	for _, cefExtension := range mapping.CEFExtensions {
		fieldName := cefExtension.Name
		fieldMapping := cefExtension.Mapping

		var value string

		// Check if this is a static extension from cef.extensions
		if staticValue, isStatic := cefConfig.Extensions[fieldName]; isStatic {
			value = staticValue
		} else {
			// Handle special built-in fields
			switch fieldName {
			case "rt":
				// Handle timestamp for CEF rt field (always epoch milliseconds)
				if timestamp != "" {
					value = ApplyTransform(timestamp, "timestamp_unix_ms")
				} else {
					value = strconv.FormatInt(time.Now().UnixMilli(), 10)
				}
			case "src":
				value = source
			case "dst":
				value = destination
			case "msg":
				value = message
			default:
				// Extract value using configured sources
				value = ExtractFieldValue(eventData, fieldMapping.Sources)

				// Apply conditions if specified
				if len(fieldMapping.Conditions) > 0 {
					for _, condition := range fieldMapping.Conditions {
						if EvaluateCondition(eventData, condition) {
							value = condition.MapTo
							break
						}
					}
				}

				// Apply transform if specified
				if fieldMapping.Transform != "" {
					value = ApplyTransform(value, fieldMapping.Transform)
				}

				// Use default if no value found
				if value == "" && fieldMapping.Default != "" {
					value = fieldMapping.Default
				}
			}
		}

		// Add to extensions if we have a value
		if value != "" {
			extensionPairs = append(extensionPairs, fmt.Sprintf("%s=%s", fieldName, escapeCEFValue(value)))
			processedFields[fieldName] = true
		}

		// Mark the source fields as processed to avoid duplicates
		for _, sourceField := range fieldMapping.Sources {
			mappedSources[sourceField] = true
		}
	}

	// Add any remaining static extensions that weren't handled in the ordered list
	for key, value := range cefConfig.Extensions {
		if !processedFields[key] {
			extensionPairs = append(extensionPairs, fmt.Sprintf("%s=%s", key, value))
			processedFields[key] = true
		}
	}

	// Add any unmapped fields from the original event data at the end
	for key, val := range eventData {
		// Skip if this field was already mapped to a CEF field
		if mappedSources[key] {
			continue
		}

		// Skip if we already have a CEF field with this name
		if processedFields[key] {
			continue
		}

		// Convert the value to string and add it
		value := fmt.Sprintf("%v", val)
		if value != "" && value != "<nil>" {
			// Use a prefix for unmapped fields to make them easily identifiable
			extensionPairs = append(extensionPairs, fmt.Sprintf("unmapped_%s=%s", key, escapeCEFValue(value)))
		}
	}

	// Format final CEF message
	if len(extensionPairs) > 0 {
		return header + "|" + strings.Join(extensionPairs, " ")
	}
	return header + "|"
}

// generateSignatureID creates a signature ID based on event type
func generateSignatureID(eventType string) string {
	if eventType == "" {
		return "1000"
	}
	hash := 0
	for _, char := range eventType {
		hash = hash*31 + int(char)
	}
	return strconv.Itoa(1000 + (hash%9000))
}

// escapeCEFField escapes CEF header fields (pipes only)
func escapeCEFField(value string) string {
	return strings.ReplaceAll(value, "|", "\\|")
}

// escapeCEFValue escapes CEF extension values
func escapeCEFValue(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "=", "\\=")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\r", "\\r")
	return value
}

// getSyslogPriority maps CEF severity to syslog priority number
func getSyslogPriority(severity string) int {
	switch severity {
	case "9", "10":
		return 2 // Critical
	case "8":
		return 3 // Error
	case "6", "7":
		return 4 // Warning
	case "0", "1", "2", "3":
		return 6 // Info
	default:
		return 5 // Notice
	}
}

// parseSyslogFacility converts facility string to facility number
func parseSyslogFacility(facility string) int {
	switch strings.ToLower(facility) {
	case "kern":
		return 0
	case "user":
		return 1
	case "mail":
		return 2
	case "daemon":
		return 3
	case "auth":
		return 4
	case "syslog":
		return 5
	case "lpr":
		return 6
	case "news":
		return 7
	case "uucp":
		return 8
	case "cron":
		return 9
	case "authpriv":
		return 10
	case "ftp":
		return 11
	case "local0":
		return 16
	case "local1":
		return 17
	case "local2":
		return 18
	case "local3":
		return 19
	case "local4":
		return 20
	case "local5":
		return 21
	case "local6":
		return 22
	case "local7":
		return 23
	default:
		return 16 // local0
	}
}

// parseTLSVersion converts TLS version string to uint16
func parseTLSVersion(version string) uint16 {
	switch strings.ToLower(version) {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12 // Default to TLS 1.2
	}
}

// parseIPsAndNetworks parses IP addresses and CIDR networks
func parseIPsAndNetworks(ips []string) (map[string]bool, []*net.IPNet, error) {
	ipMap := make(map[string]bool)
	var networks []*net.IPNet

	for _, ipStr := range ips {
		if strings.Contains(ipStr, "/") {
			// CIDR network
			_, network, err := net.ParseCIDR(ipStr)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid CIDR network %s: %w", ipStr, err)
			}
			networks = append(networks, network)
		} else {
			// Individual IP
			if net.ParseIP(ipStr) == nil {
				return nil, nil, fmt.Errorf("invalid IP address: %s", ipStr)
			}
			ipMap[ipStr] = true
		}
	}

	return ipMap, networks, nil
}

// Middleware for resource protection
func (ep *EventProcessor) protectionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Panic recovery
		if ep.config.Protection.EnablePanicRecovery {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("Panic recovered: %v", rec)
					http.Error(w, "Internal server error", http.StatusInternalServerError)
				}
			}()
		}

		// Check memory usage
		if !ep.CheckMemoryUsage() {
			http.Error(w, "Service temporarily unavailable - memory limit exceeded", http.StatusServiceUnavailable)
			return
		}

		// Check concurrent requests
		maxConcurrent := ep.config.Protection.MaxConcurrentReqs
		if maxConcurrent > 0 {
			current := atomic.AddInt64(&ep.concurrentReqs, 1)
			defer atomic.AddInt64(&ep.concurrentReqs, -1)

			if current > int64(maxConcurrent) {
				http.Error(w, "Too many concurrent requests", http.StatusTooManyRequests)
				return
			}
		}

		// Set request timeout
		if ep.config.Protection.RequestTimeout != "" {
			timeout := parseDuration(ep.config.Protection.RequestTimeout, 30*time.Second)
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()
			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	})
}

// Enhanced request size limiting
func (ep *EventProcessor) enhancedSizeLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Multiple layers of size protection
		maxSize := ep.config.Server.MaxBodySize
		if maxSize == 0 {
			maxSize = 1048576 // 1MB default
		}

		// Check Content-Length header first
		if r.ContentLength > maxSize {
			http.Error(w, fmt.Sprintf("Request body too large: %d > %d", r.ContentLength, maxSize), http.StatusRequestEntityTooLarge)
			return
		}

		// Wrap the request body with protected reader
		timeout := parseDuration(ep.config.Protection.RequestTimeout, 30*time.Second)
		r.Body = io.NopCloser(NewProtectedReader(r.Body, maxSize, timeout))

		next.ServeHTTP(w, r)
	})
}

// Circuit breaker middleware
func (ep *EventProcessor) circuitBreakerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ep.config.Protection.EnableCircuitBreaker && ep.circuitBreaker != nil {
			err := ep.circuitBreaker.Call(func() error {
				next.ServeHTTP(w, r)
				return nil
			})
			if err != nil {
				http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

// NewEventProcessor creates a new event processor with enhanced protection
func NewEventProcessor(config *Config) (*EventProcessor, error) {
	var syslogForwarder *SyslogForwarder
	var err error

	// Only create syslog forwarder if not in local-only mode AND we have a syslog address
	if !config.Logging.LocalOnly && config.Syslog.Address != "" {
		syslogForwarder, err = NewSyslogForwarder(&config.Syslog)
		if err != nil {
			return nil, fmt.Errorf("failed to create syslog forwarder: %w", err)
		}
	}

	// Create rate limiter
	burst := config.Security.RateBurst
	if burst == 0 {
		burst = config.Security.RateLimit * 2
	}
	limiter := rate.NewLimiter(rate.Limit(config.Security.RateLimit), burst)

	// Parse allowed IPs and networks
	allowedIPs, allowedNetworks, err := parseIPsAndNetworks(config.Security.AllowedIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse allowed IPs: %w", err)
	}

	// Parse blocked IPs and networks
	blockedIPs, blockedNetworks, err := parseIPsAndNetworks(config.Security.BlockedIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse blocked IPs: %w", err)
	}

	processor := &EventProcessor{
		syslogForwarder: syslogForwarder,
		limiter:         limiter,
		config:          config,
		allowedIPs:      allowedIPs,
		allowedNetworks: allowedNetworks,
		blockedIPs:      blockedIPs,
		blockedNetworks: blockedNetworks,
	}

	// Initialize circuit breaker
	if config.Protection.EnableCircuitBreaker {
		threshold := config.Protection.CircuitBreakerLimit
		if threshold == 0 {
			threshold = 10
		}
		processor.circuitBreaker = NewCircuitBreaker(threshold)
	}

	// Compile syslog regex if configured
	if config.Parsing.SyslogRegex != "" {
		processor.syslogRegex, err = regexp.Compile(config.Parsing.SyslogRegex)
		if err != nil {
			return nil, fmt.Errorf("invalid syslog regex: %w", err)
		}
	} else {
		// Default syslog regex
		defaultRegex := `^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\w+)(?:\[(\d+)\])?\s*:\s*(.*)$`
		processor.syslogRegex, _ = regexp.Compile(defaultRegex)
	}

	// Setup local logging if local log file is specified
	if config.Logging.LocalLogFile != "" {
		if err := processor.setupLocalLogging(); err != nil {
			return nil, fmt.Errorf("failed to setup local logging: %w", err)
		}
	}

	// Start memory monitor
	processor.StartMemoryMonitor()

	return processor, nil
}

// setupLocalLogging configures local file logging
func (ep *EventProcessor) setupLocalLogging() error {
	if ep.config.Logging.LocalLogFile == "" {
		return fmt.Errorf("local log file not specified")
	}

	file, err := os.OpenFile(ep.config.Logging.LocalLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	ep.localLogFile = file
	ep.localLogger = log.New(file, "", log.LstdFlags)
	return nil
}

// ProcessMessage processes a message of any format
func (ep *EventProcessor) ProcessMessage(rawMessage string) error {
	// Parse the message into our internal format
	parsed, err := ep.ParseMessage(rawMessage)
	if err != nil {
		return fmt.Errorf("failed to parse message: %w", err)
	}

	// Convert to CEF format
	cefMessage := ep.ConvertToCEF(parsed.Data)

	// Always log locally if local_log_file is configured (regardless of local_only setting)
	if ep.localLogger != nil {
		ep.localLogger.Printf("FORMAT: %s | CEF: %s", parsed.Format, cefMessage)
		if ep.config.Logging.LocalOnly {
			// Also log original message and parsed data for debugging when in local-only mode
			ep.localLogger.Printf("RAW: %s", parsed.OriginalText)
			if jsonData, err := json.Marshal(parsed.Data); err == nil {
				ep.localLogger.Printf("PARSED: %s", string(jsonData))
			}
		}
	}

	// Forward to syslog if not in local-only mode
	if !ep.config.Logging.LocalOnly && ep.syslogForwarder != nil {
		// Extract severity for syslog priority
		severity := ExtractFieldValue(parsed.Data, ep.config.FieldMapping.SeverityField)
		if mappedSeverity, exists := ep.config.FieldMapping.SeverityMap[strings.ToLower(severity)]; exists {
			severity = mappedSeverity
		}

		priority := getSyslogPriority(severity)

		// Forward to syslog
		return ep.syslogForwarder.Forward(priority, cefMessage)
	}

	return nil
}

// ProcessEvent processes a single event (backwards compatibility)
func (ep *EventProcessor) ProcessEvent(eventData map[string]interface{}) error {
	// Convert to CEF format
	cefMessage := ep.ConvertToCEF(eventData)

	// Always log locally if local_log_file is configured (regardless of local_only setting)
	if ep.localLogger != nil {
		ep.localLogger.Printf("FORMAT: json | CEF: %s", cefMessage)
		if ep.config.Logging.LocalOnly {
			// Also log original event data for debugging when in local-only mode
			if jsonData, err := json.Marshal(eventData); err == nil {
				ep.localLogger.Printf("RAW: %s", string(jsonData))
			}
		}
	}

	// Forward to syslog if not in local-only mode
	if !ep.config.Logging.LocalOnly && ep.syslogForwarder != nil {
		// Extract severity for syslog priority
		severity := ExtractFieldValue(eventData, ep.config.FieldMapping.SeverityField)
		if mappedSeverity, exists := ep.config.FieldMapping.SeverityMap[strings.ToLower(severity)]; exists {
			severity = mappedSeverity
		}

		priority := getSyslogPriority(severity)

		// Forward to syslog
		return ep.syslogForwarder.Forward(priority, cefMessage)
	}

	return nil
}

// Close closes the event processor
func (ep *EventProcessor) Close() {
	if ep.syslogForwarder != nil {
		ep.syslogForwarder.Close()
	}
	if ep.localLogFile != nil {
		ep.localLogFile.Close()
	}
}

// isIPAllowed checks if an IP is allowed
func (ep *EventProcessor) isIPAllowed(clientIP string) bool {
	// Check for special allow-all cases first
	if len(ep.allowedIPs) > 0 {
		// Check for wildcard/allow-all entries
		if ep.allowedIPs["0.0.0.0"] || ep.allowedIPs["any"] {
			return true
		}
	}

	// Check blocked IPs first (unless we have an allow-all)
	if ep.blockedIPs[clientIP] {
		return false
	}

	// Check blocked networks
	ip := net.ParseIP(clientIP)
	if ip != nil {
		for _, network := range ep.blockedNetworks {
			if network.Contains(ip) {
				return false
			}
		}
	}

	// No restrictions if no allowed IPs configured
	if len(ep.allowedIPs) == 0 && len(ep.allowedNetworks) == 0 {
		return true
	}

	// Check individual allowed IPs
	if ep.allowedIPs[clientIP] {
		return true
	}

	// Check allowed networks
	if ip != nil {
		for _, network := range ep.allowedNetworks {
			if network.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// Middleware for IP filtering
func (ep *EventProcessor) ipFilterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		if !ep.isIPAllowed(clientIP) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Middleware for authentication
func (ep *EventProcessor) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ep.config.Security.EnableAuth {
			next.ServeHTTP(w, r)
			return
		}

		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				apiKey = authHeader[7:]
			}
		}

		validKey := false
		for _, validAPIKey := range ep.config.Security.APIKeys {
			if subtle.ConstantTimeCompare([]byte(apiKey), []byte(validAPIKey)) == 1 {
				validKey = true
				break
			}
		}

		if !validKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Middleware for rate limiting
func (ep *EventProcessor) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ep.config.Security.RateLimit > 0 && !ep.limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// HTTP handler for index page
func (ep *EventProcessor) handleIndex(w http.ResponseWriter, r *http.Request) {
	if !ep.config.Web.EnableIndex {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	if ep.config.Web.IndexPage != "" {
		http.ServeFile(w, r, ep.config.Web.IndexPage)
	} else {
		// Default index page
		defaultIndex := `<!DOCTYPE html>
<html>
<head>
    <title>Event Forwarder</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .status { padding: 10px; background: #d4edda; border: 1px solid #c3e6cb; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Event Forwarder</h1>
        <div class="status">
            <strong>Status:</strong> Service is running
        </div>
        <h2>API Endpoints</h2>
        <ul>
            <li><code>POST /events</code> - Submit events for processing (accepts JSON, syslog, CEF, key-value, CSV, or plain text)</li>
            <li><code>GET /health</code> - Health check endpoint</li>
        </ul>
        <h2>Supported Formats</h2>
        <ul>
            <li><strong>JSON:</strong> <code>{"event_type":"test","severity":"info","message":"Test event"}</code></li>
            <li><strong>Syslog:</strong> <code>Jan 15 10:00:00 hostname program[123]: message</code></li>
            <li><strong>CEF:</strong> <code>CEF:0|Vendor|Product|1.0|123|Test|3|msg=Test event</code></li>
            <li><strong>Key-Value:</strong> <code>event_type=test severity=info message="Test event"</code></li>
            <li><strong>Plain Text:</strong> Any unstructured text message</li>
        </ul>
    </div>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(defaultIndex))
	}
}

// Enhanced events handler with better error handling
func (ep *EventProcessor) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read request body with timeout protection
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed to read request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	rawMessage := strings.TrimSpace(string(body))
	if rawMessage == "" {
		http.Error(w, "Empty message body", http.StatusBadRequest)
		return
	}

	// Process with circuit breaker protection
	processFunc := func() error {
		// Try JSON parsing first for backwards compatibility
		var eventData map[string]interface{}
		if err := json.Unmarshal(body, &eventData); err == nil {
			return ep.ProcessEvent(eventData)
		} else {
			// Try JSON array
			var events []map[string]interface{}
			if err := json.Unmarshal(body, &events); err == nil {
				for _, event := range events {
					if err := ep.ProcessEvent(event); err != nil {
						log.Printf("Failed to process JSON array event: %v", err)
						return err
					}
				}
				return nil
			} else {
				// Use universal message parsing
				return ep.ProcessMessage(rawMessage)
			}
		}
	}

	if ep.config.Protection.EnableCircuitBreaker && ep.circuitBreaker != nil {
		err = ep.circuitBreaker.Call(processFunc)
	} else {
		err = processFunc()
	}

	if err != nil {
		log.Printf("Failed to process message: %v", err)
		http.Error(w, "Failed to process message", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Health check handler
func (ep *EventProcessor) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// LoadConfig loads configuration from JSON file
func LoadConfig(configFile string) (*Config, error) {
	file, err := os.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set protection defaults
	if config.Protection.MaxMemoryMB == 0 {
		config.Protection.MaxMemoryMB = 512 // 512MB default
	}
	if config.Protection.MaxConcurrentReqs == 0 {
		config.Protection.MaxConcurrentReqs = 100
	}
	if config.Protection.RequestTimeout == "" {
		config.Protection.RequestTimeout = "30s"
	}
	if config.Protection.MaxJSONDepth == 0 {
		config.Protection.MaxJSONDepth = 10
	}
	if config.Protection.MaxFieldCount == 0 {
		config.Protection.MaxFieldCount = 100
	}
	if config.Protection.MaxFieldValueLength == 0 {
		config.Protection.MaxFieldValueLength = 10000
	}
	if config.Protection.MemoryCheckInterval == "" {
		config.Protection.MemoryCheckInterval = "30s"
	}
	if config.Protection.CircuitBreakerLimit == 0 {
		config.Protection.CircuitBreakerLimit = 10
	}

	config.Protection.EnablePanicRecovery = true
	config.Protection.EnableCircuitBreaker = true

	// Set server defaults
	if config.Server.ListenAddr == "" {
		config.Server.ListenAddr = ":8443"
	}
	if config.Server.MaxBodySize == 0 {
		config.Server.MaxBodySize = 1048576 // 1MB
	}
	if config.Server.MaxHeaderBytes == 0 {
		config.Server.MaxHeaderBytes = 1048576 // 1MB
	}
	if config.Server.ReadTimeout == "" {
		config.Server.ReadTimeout = "10s"
	}
	if config.Server.WriteTimeout == "" {
		config.Server.WriteTimeout = "10s"
	}
	if config.Server.IdleTimeout == "" {
		config.Server.IdleTimeout = "120s"
	}
	if config.Server.ReadHeaderTimeout == "" {
		config.Server.ReadHeaderTimeout = "5s"
	}
	if config.Server.ShutdownTimeout == "" {
		config.Server.ShutdownTimeout = "30s"
	}
	if config.Server.TLSMinVersion == "" {
		config.Server.TLSMinVersion = "1.2"
	}

	if config.Syslog.PoolSize == 0 {
		config.Syslog.PoolSize = 10
	}
	if config.Syslog.Protocol == "" {
		config.Syslog.Protocol = "udp"
	}
	if config.Syslog.ConnectTimeout == "" {
		config.Syslog.ConnectTimeout = "5s"
	}
	if config.Syslog.WriteTimeout == "" {
		config.Syslog.WriteTimeout = "2s"
	}
	if config.Syslog.RetryInterval == "" {
		config.Syslog.RetryInterval = "5s"
	}
	if config.Syslog.MaxRetries == 0 {
		config.Syslog.MaxRetries = 3
	}
	if config.Syslog.TimestampFormat == "" {
		config.Syslog.TimestampFormat = "Jan _2 15:04:05"
	}

	if config.CEF.Version == "" {
		config.CEF.Version = "0"
	}

	if config.Security.RateLimit == 0 {
		config.Security.RateLimit = 1000
	}
	if config.Security.RateLimitWindow == "" {
		config.Security.RateLimitWindow = "1s"
	}

	if config.Logging.LogLevel == "" {
		config.Logging.LogLevel = "info"
	}

	// Set parsing defaults
	if config.Parsing.DefaultEventType == "" {
		config.Parsing.DefaultEventType = "unknown"
	}
	if config.Parsing.DefaultSeverity == "" {
		config.Parsing.DefaultSeverity = "info"
	}

	return &config, nil
}

// parseDuration safely parses duration strings
func parseDuration(s string, defaultDuration time.Duration) time.Duration {
	if s == "" {
		return defaultDuration
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return defaultDuration
}

// findConfigFile looks for config files in common locations
func findConfigFile() string {
	candidates := []string{
		"config.json",
		"event-forwarder.json",
		"./config/config.json",
		"/etc/event-forwarder/config.json",
		"/usr/local/etc/event-forwarder/config.json",
	}

	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	return ""
}

func main() {
	var configFile string
	flag.StringVar(&configFile, "config", "", "Path to configuration file")
	flag.Parse()

	if configFile == "" {
		configFile = findConfigFile()
		if configFile == "" {
			log.Fatal("No configuration file found. Use -config flag to specify one.")
		}
		log.Printf("Using configuration file: %s", configFile)
	}

	config, err := LoadConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	processor, err := NewEventProcessor(config)
	if err != nil {
		log.Fatalf("Failed to create event processor: %v", err)
	}
	defer processor.Close()

	mux := http.NewServeMux()

	// Enhanced middleware chain with protection
	eventsHandler := processor.enhancedSizeLimitMiddleware(
		processor.protectionMiddleware(
			processor.circuitBreakerMiddleware(
				processor.rateLimitMiddleware(
					processor.authMiddleware(
						processor.ipFilterMiddleware(
							http.HandlerFunc(processor.handleEvents)))))))

	indexHandler := processor.ipFilterMiddleware(
		http.HandlerFunc(processor.handleIndex))

	mux.Handle("/", indexHandler)
	mux.Handle("/events", eventsHandler)
	mux.HandleFunc("/health", processor.handleHealth)

	if config.Web.StaticDir != "" {
		fileServer := http.FileServer(http.Dir(config.Web.StaticDir))
		staticHandler := processor.ipFilterMiddleware(
			http.StripPrefix("/static/", fileServer))
		mux.Handle("/static/", staticHandler)
	}

	tlsConfig := &tls.Config{
		MinVersion: parseTLSVersion(config.Server.TLSMinVersion),
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	if !config.Server.EnableHTTP2 {
		tlsConfig.NextProtos = []string{"http/1.1"}
	}

	server := &http.Server{
		Addr:              config.Server.ListenAddr,
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadTimeout:       parseDuration(config.Server.ReadTimeout, 10*time.Second),
		WriteTimeout:      parseDuration(config.Server.WriteTimeout, 10*time.Second),
		IdleTimeout:       parseDuration(config.Server.IdleTimeout, 120*time.Second),
		ReadHeaderTimeout: parseDuration(config.Server.ReadHeaderTimeout, 5*time.Second),
		MaxHeaderBytes:    config.Server.MaxHeaderBytes,
	}

	go func() {
		log.Printf("Starting HTTPS server on %s with enhanced protection", config.Server.ListenAddr)
		log.Printf("Memory limit: %dMB, Max concurrent: %d, Request timeout: %s",
			config.Protection.MaxMemoryMB,
			config.Protection.MaxConcurrentReqs,
			config.Protection.RequestTimeout)

		if err := server.ListenAndServeTLS(config.Server.TLSCertFile, config.Server.TLSKeyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	shutdownTimeout := parseDuration(config.Server.ShutdownTimeout, 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

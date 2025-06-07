package core

import (
	"os"

	"github.com/sirupsen/logrus"
)

var globalLogger *logrus.Logger

// NewLogger crée une nouvelle instance de logger
func NewLogger(verbose bool) *logrus.Logger {
	logger := logrus.New()

	// Configuration du format
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		ForceColors:   true,
	})

	// Niveau de log
	if verbose {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	// Sortie
	logger.SetOutput(os.Stdout)

	globalLogger = logger
	return logger
}

// GetLogger retourne le logger global
func GetLogger() *logrus.Logger {
	if globalLogger == nil {
		return NewLogger(false)
	}
	return globalLogger
}

// LogLevel représente un niveau de log
type LogLevel string

const (
	DebugLevel LogLevel = "debug"
	InfoLevel  LogLevel = "info"
	WarnLevel  LogLevel = "warn"
	ErrorLevel LogLevel = "error"
	FatalLevel LogLevel = "fatal"
)

// SetLogLevel définit le niveau de log global
func SetLogLevel(level LogLevel) {
	logger := GetLogger()

	switch level {
	case DebugLevel:
		logger.SetLevel(logrus.DebugLevel)
	case InfoLevel:
		logger.SetLevel(logrus.InfoLevel)
	case WarnLevel:
		logger.SetLevel(logrus.WarnLevel)
	case ErrorLevel:
		logger.SetLevel(logrus.ErrorLevel)
	case FatalLevel:
		logger.SetLevel(logrus.FatalLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}
}

// LogEntry représente une entrée de log structurée
type LogEntry struct {
	Level     LogLevel               `json:"level"`
	Message   string                 `json:"message"`
	Timestamp string                 `json:"timestamp"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// StructuredLogger permet un logging structuré pour les scans
type StructuredLogger struct {
	logger *logrus.Logger
	fields logrus.Fields
}

// NewStructuredLogger crée un nouveau logger structuré
func NewStructuredLogger(component string) *StructuredLogger {
	return &StructuredLogger{
		logger: GetLogger(),
		fields: logrus.Fields{
			"component": component,
		},
	}
}

// WithField ajoute un champ au logger
func (sl *StructuredLogger) WithField(key string, value interface{}) *StructuredLogger {
	newFields := make(logrus.Fields)
	for k, v := range sl.fields {
		newFields[k] = v
	}
	newFields[key] = value

	return &StructuredLogger{
		logger: sl.logger,
		fields: newFields,
	}
}

// WithFields ajoute plusieurs champs au logger
func (sl *StructuredLogger) WithFields(fields map[string]interface{}) *StructuredLogger {
	newFields := make(logrus.Fields)
	for k, v := range sl.fields {
		newFields[k] = v
	}
	for k, v := range fields {
		newFields[k] = v
	}

	return &StructuredLogger{
		logger: sl.logger,
		fields: newFields,
	}
}

// Debug log un message de debug
func (sl *StructuredLogger) Debug(msg string) {
	sl.logger.WithFields(sl.fields).Debug(msg)
}

// Info log un message d'information
func (sl *StructuredLogger) Info(msg string) {
	sl.logger.WithFields(sl.fields).Info(msg)
}

// Warn log un message d'avertissement
func (sl *StructuredLogger) Warn(msg string) {
	sl.logger.WithFields(sl.fields).Warn(msg)
}

// Error log un message d'erreur
func (sl *StructuredLogger) Error(msg string) {
	sl.logger.WithFields(sl.fields).Error(msg)
}

// Fatal log un message fatal et termine le programme
func (sl *StructuredLogger) Fatal(msg string) {
	sl.logger.WithFields(sl.fields).Fatal(msg)
}

// Debugf log un message de debug formaté
func (sl *StructuredLogger) Debugf(format string, args ...interface{}) {
	sl.logger.WithFields(sl.fields).Debugf(format, args...)
}

// Infof log un message d'information formaté
func (sl *StructuredLogger) Infof(format string, args ...interface{}) {
	sl.logger.WithFields(sl.fields).Infof(format, args...)
}

// Warnf log un message d'avertissement formaté
func (sl *StructuredLogger) Warnf(format string, args ...interface{}) {
	sl.logger.WithFields(sl.fields).Warnf(format, args...)
}

// Errorf log un message d'erreur formaté
func (sl *StructuredLogger) Errorf(format string, args ...interface{}) {
	sl.logger.WithFields(sl.fields).Errorf(format, args...)
}

// Fatalf log un message fatal formaté et termine le programme
func (sl *StructuredLogger) Fatalf(format string, args ...interface{}) {
	sl.logger.WithFields(sl.fields).Fatalf(format, args...)
}

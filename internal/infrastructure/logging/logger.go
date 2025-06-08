package logging

import (
	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
	"github.com/riadh-benchouche/security-audit-tool/internal/scanners/interfaces"
	"github.com/sirupsen/logrus"
	"os"
)

var globalLogger *logrus.Logger

// Logger implémente l'interface ScannerLogger
type Logger struct {
	logger *logrus.Logger
	fields logrus.Fields
}

// NewLogger crée une nouvelle instance de logger
func NewLogger(verbose bool) *Logger {
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

	return &Logger{
		logger: logger,
		fields: make(logrus.Fields),
	}
}

// GetGlobalLogger retourne le logger global
func GetGlobalLogger() *Logger {
	if globalLogger == nil {
		return NewLogger(false)
	}
	return &Logger{
		logger: globalLogger,
		fields: make(logrus.Fields),
	}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, fields map[string]interface{}) {
	entry := l.logger.WithFields(l.fields)
	if fields != nil {
		entry = entry.WithFields(logrus.Fields(fields))
	}
	entry.Debug(msg)
}

// Info logs an info message
func (l *Logger) Info(msg string, fields map[string]interface{}) {
	entry := l.logger.WithFields(l.fields)
	if fields != nil {
		entry = entry.WithFields(logrus.Fields(fields))
	}
	entry.Info(msg)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, fields map[string]interface{}) {
	entry := l.logger.WithFields(l.fields)
	if fields != nil {
		entry = entry.WithFields(logrus.Fields(fields))
	}
	entry.Warn(msg)
}

// Error logs an error message
func (l *Logger) Error(msg string, err error, fields map[string]interface{}) {
	entry := l.logger.WithFields(l.fields)
	if fields != nil {
		entry = entry.WithFields(logrus.Fields(fields))
	}
	if err != nil {
		entry = entry.WithError(err)
	}
	entry.Error(msg)
}

// WithField returns a logger with an additional field
func (l *Logger) WithField(key string, value interface{}) interfaces.ScannerLogger {
	newFields := make(logrus.Fields)
	for k, v := range l.fields {
		newFields[k] = v
	}
	newFields[key] = value

	return &Logger{
		logger: l.logger,
		fields: newFields,
	}
}

// WithFields returns a logger with additional fields
func (l *Logger) WithFields(fields map[string]interface{}) interfaces.ScannerLogger {
	newFields := make(logrus.Fields)
	for k, v := range l.fields {
		newFields[k] = v
	}
	for k, v := range fields {
		newFields[k] = v
	}

	return &Logger{
		logger: l.logger,
		fields: newFields,
	}
}

// WithScanner returns a logger with scanner context
func (l *Logger) WithScanner(name string) interfaces.ScannerLogger {
	return l.WithField("scanner", name)
}

// WithTarget returns a logger with target context
func (l *Logger) WithTarget(target *entities.Target) interfaces.ScannerLogger {
	return l.WithFields(map[string]interface{}{
		"target":      target.Original(),
		"target_type": target.Type().String(),
		"target_host": target.Host(),
	})
}

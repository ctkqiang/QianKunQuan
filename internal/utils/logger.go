package utils

import (
	"fmt"
	"log"
	"os"
	"time"
)

type Logger struct {
	name   string
	logger *log.Logger
	debug  bool
}

func NewLogger(name string) *Logger {
	return &Logger{
		name:   name,
		logger: log.New(os.Stdout, "", 0),
		debug:  os.Getenv("DEBUG") == "true",
	}
}

func (l *Logger) Info(format string, args ...interface{}) {
	prefix := fmt.Sprintf("[%s][INFO][%s] ", l.name, time.Now().Format("15:04:05"))
	l.logger.Printf(prefix+format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	prefix := fmt.Sprintf("[%s][ERROR][%s] ", l.name, time.Now().Format("15:04:05"))
	l.logger.Printf(prefix+format, args...)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.debug {
		prefix := fmt.Sprintf("[%s][DEBUG][%s] ", l.name, time.Now().Format("15:04:05"))
		l.logger.Printf(prefix+format, args...)
	}
}

// 添加Warn方法
func (l *Logger) Warn(format string, args ...interface{}) {
	prefix := fmt.Sprintf("[%s][WARN][%s] ", l.name, time.Now().Format("15:04:05"))
	l.logger.Printf(prefix+format, args...)
}

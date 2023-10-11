package statute

import "fmt"

type Logger interface {
	Debug(v ...interface{})
	Error(v ...interface{})
}

type DefaultLogger struct{}

func (l DefaultLogger) Debug(v ...interface{}) {
	fmt.Println(v...)
}

func (l DefaultLogger) Error(v ...interface{}) {
	fmt.Println(v...)
}

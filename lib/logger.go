package lib

import (
	"io"
	"os"

	"github.com/rs/zerolog"
)

type SpecificLevelWriter struct {
	io.Writer
	Levels []zerolog.Level
}

func (w SpecificLevelWriter) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	for _, l := range w.Levels {
		if l == level {
			return w.Write(p)
		}
	}
	return len(p), nil
}

func CreateLogger(minimumLevel zerolog.Level) zerolog.Logger {
	writer := zerolog.MultiLevelWriter(
		SpecificLevelWriter{
			Writer: zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"},
			Levels: []zerolog.Level{
				zerolog.DebugLevel, zerolog.InfoLevel, zerolog.WarnLevel,
			},
		},
		SpecificLevelWriter{
			Writer: zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"},
			Levels: []zerolog.Level{
				zerolog.ErrorLevel, zerolog.FatalLevel, zerolog.PanicLevel,
			},
		},
	)

	return zerolog.New(writer).Level(minimumLevel).With().Timestamp().Logger()
}

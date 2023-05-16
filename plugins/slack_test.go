package plugins

import (
	"strconv"
	"testing"
	"time"

	"github.com/slack-go/slack"
)

func formatSecondsAnd6DigitsMiliseconds(t time.Time) string {
	n := float64(t.UnixMicro()) / float64(time.Millisecond)
	return strconv.FormatFloat(n, 'f', 6, 64)
}

const (
	noLimit = 0
)

func TestIsMessageOutOfRange(t *testing.T) {
	tests := []struct {
		name                 string
		message              slack.Message
		backwardDuration     time.Duration
		currentMessagesCount int
		limitMessagesCount   int
		expectedOutOfRange   bool
	}{
		{
			name: "message is within range",
			message: slack.Message{
				Msg: slack.Msg{
					Timestamp: formatSecondsAnd6DigitsMiliseconds(timeNow),
				},
			},
			backwardDuration:     time.Minute,
			currentMessagesCount: 0,
			limitMessagesCount:   noLimit,
			expectedOutOfRange:   false,
		},
		{
			name: "message is out of range due to backward duration",
			message: slack.Message{
				Msg: slack.Msg{
					Timestamp: formatSecondsAnd6DigitsMiliseconds(timeNow.Add(-time.Minute * 2)),
				},
			},
			backwardDuration:     time.Minute,
			currentMessagesCount: 0,
			limitMessagesCount:   noLimit,
			expectedOutOfRange:   true,
		},
		{
			name: "message is out of range due to message count limit",
			message: slack.Message{
				Msg: slack.Msg{
					Timestamp: formatSecondsAnd6DigitsMiliseconds(timeNow),
				},
			},
			backwardDuration:     noLimit,
			currentMessagesCount: 1,
			limitMessagesCount:   1,
			expectedOutOfRange:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outOfRange, err := isMessageOutOfRange(tt.message, tt.backwardDuration, tt.currentMessagesCount, tt.limitMessagesCount)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if outOfRange != tt.expectedOutOfRange {
				t.Errorf("expected outOfRange to be %v, but got %v", tt.expectedOutOfRange, outOfRange)
			}
		})
	}
}

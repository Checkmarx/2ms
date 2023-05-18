package plugins

import (
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/slack-go/slack"
)

type mockSlackClient struct {
	channels []slack.Channel
	err      error
}

func (m *mockSlackClient) GetConversations(params *slack.GetConversationsParameters) ([]slack.Channel, string, error) {
	return m.channels, "", m.err
}
func (m *mockSlackClient) ListTeams(params slack.ListTeamsParameters) ([]slack.Team, string, error) {
	return nil, "", errors.New("not implemented")
}

func TestGetChannels(t *testing.T) {

	tests := []struct {
		name           string
		slackApi       mockSlackClient
		teamId         string
		wantedChannels []string
		expectedResult []slack.Channel
		expectedError  error
	}{
		{
			name: "get all channels",
			slackApi: mockSlackClient{
				channels: []slack.Channel{
					{GroupConversation: slack.GroupConversation{Name: "channel1", Conversation: slack.Conversation{ID: "C123456"}}},
					{GroupConversation: slack.GroupConversation{Name: "channel2", Conversation: slack.Conversation{ID: "C234567"}}},
				},
			},
			teamId:         "T123456",
			wantedChannels: []string{},
			expectedResult: []slack.Channel{
				{GroupConversation: slack.GroupConversation{Name: "channel1", Conversation: slack.Conversation{ID: "C123456"}}},
				{GroupConversation: slack.GroupConversation{Name: "channel2", Conversation: slack.Conversation{ID: "C234567"}}},
			},
			expectedError: nil,
		},
		{
			name: "get specific channels",
			slackApi: mockSlackClient{
				channels: []slack.Channel{
					{GroupConversation: slack.GroupConversation{Name: "channel1", Conversation: slack.Conversation{ID: "C123456"}}},
					{GroupConversation: slack.GroupConversation{Name: "channel2", Conversation: slack.Conversation{ID: "C234567"}}},
				},
			},
			teamId:         "T123456",
			wantedChannels: []string{"channel1", "C234567"},
			expectedResult: []slack.Channel{
				{GroupConversation: slack.GroupConversation{Name: "channel1", Conversation: slack.Conversation{ID: "C123456"}}},
				{GroupConversation: slack.GroupConversation{Name: "channel2", Conversation: slack.Conversation{ID: "C234567"}}},
			},
			expectedError: nil,
		},
		{
			name: "get specific channels not found",
			slackApi: mockSlackClient{
				channels: []slack.Channel{
					{GroupConversation: slack.GroupConversation{Name: "channel1", Conversation: slack.Conversation{ID: "C123456"}}},
					{GroupConversation: slack.GroupConversation{Name: "channel2", Conversation: slack.Conversation{ID: "C234567"}}},
				},
			},
			teamId:         "T123456",
			wantedChannels: []string{"channel3", "C345678"},
			expectedResult: []slack.Channel{},
			expectedError:  nil,
		},
		{
			name: "get channels error",
			slackApi: mockSlackClient{
				err:      fmt.Errorf("some error"),
				channels: []slack.Channel{},
			},
			teamId:         "T123456",
			wantedChannels: []string{},
			expectedResult: []slack.Channel{},
			expectedError:  fmt.Errorf("error while getting channels: %w", errors.New("some error")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getChannels(&tt.slackApi, tt.teamId, tt.wantedChannels)
			if err != nil && tt.expectedError == nil {
				t.Errorf("unexpected error: %v", err)
			}
			if err == nil && tt.expectedError != nil {
				t.Errorf("expected error: %v, but got nil", tt.expectedError)
			}
			if err != nil && tt.expectedError != nil {
				return
			}
			if len(*result) != len(tt.expectedResult) {
				t.Errorf("expected %d channels, but got %d", len(tt.expectedResult), len(*result))
			}
			for i, c := range *result {
				if c.Name != tt.expectedResult[i].Name || c.ID != tt.expectedResult[i].ID {
					t.Errorf("expected channel %v, but got %v", tt.expectedResult[i], c)
				}
			}
		})
	}
}

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

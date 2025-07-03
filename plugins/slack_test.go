package plugins

import (
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/slack-go/slack"
)

type ListTeamsResponse struct {
	Teams  []slack.Team
	Cursor string
	Err    error
}

type mockSlackClient struct {
	channels           []slack.Channel
	err                error
	listTeamsResponses []ListTeamsResponse
}

func (m *mockSlackClient) GetConversations(params *slack.GetConversationsParameters) ([]slack.Channel, string, error) {
	return m.channels, "", m.err
}
func (m *mockSlackClient) ListTeams(params slack.ListTeamsParameters) ([]slack.Team, string, error) {
	if len(m.listTeamsResponses) == 0 {
		return nil, "", nil
	}
	response := m.listTeamsResponses[0]
	m.listTeamsResponses = m.listTeamsResponses[1:]
	return response.Teams, response.Cursor, response.Err
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
			outOfRange, err := isMessageOutOfRange(&tt.message, tt.backwardDuration, tt.currentMessagesCount, tt.limitMessagesCount)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if outOfRange != tt.expectedOutOfRange {
				t.Errorf("expected outOfRange to be %v, but got %v", tt.expectedOutOfRange, outOfRange)
			}
		})
	}
}

func TestGetTeam(t *testing.T) {
	tests := []struct {
		name              string
		teamNameToSearch  string
		mockResponses     []ListTeamsResponse
		expectedTeam      *slack.Team
		expectedErrSubstr string
	}{
		{
			name:             "ListTeams returns error",
			teamNameToSearch: "AnyTeam",
			mockResponses: []ListTeamsResponse{
				{
					Teams:  nil,
					Cursor: "",
					Err:    errors.New("some error"),
				},
			},
			expectedTeam:      nil,
			expectedErrSubstr: "error while getting teams",
		},
		{
			name:             "Team found by Name on first page",
			teamNameToSearch: "TeamA",
			mockResponses: []ListTeamsResponse{
				{
					Teams: []slack.Team{
						{ID: "2", Name: "OtherTeam"},
						{ID: "1", Name: "TeamA"},
					},
					Cursor: "",
					Err:    nil,
				},
			},
			expectedTeam:      &slack.Team{ID: "1", Name: "TeamA"},
			expectedErrSubstr: "",
		},
		{
			name:             "Team found by ID on first page",
			teamNameToSearch: "TeamB",
			mockResponses: []ListTeamsResponse{
				{
					Teams: []slack.Team{
						{ID: "1", Name: "OtherTeam"},
						{ID: "TeamB", Name: "SomeTeam"},
					},
					Cursor: "",
					Err:    nil,
				},
			},
			expectedTeam:      &slack.Team{ID: "TeamB", Name: "SomeTeam"},
			expectedErrSubstr: "",
		},
		{
			name:             "Team found in second page",
			teamNameToSearch: "TeamC",
			mockResponses: []ListTeamsResponse{
				{
					Teams: []slack.Team{
						{ID: "1", Name: "OtherTeam"},
					},
					Cursor: "cursor1",
					Err:    nil,
				},
				{
					Teams: []slack.Team{
						{ID: "3", Name: "TeamC"},
					},
					Cursor: "",
					Err:    nil,
				},
			},
			expectedTeam:      &slack.Team{ID: "3", Name: "TeamC"},
			expectedErrSubstr: "",
		},
		{
			name:             "Team not found",
			teamNameToSearch: "TeamNotFound",
			mockResponses: []ListTeamsResponse{
				{
					Teams: []slack.Team{
						{ID: "1", Name: "OtherTeam1"},
					},
					Cursor: "cursor1",
					Err:    nil,
				},
				{
					Teams: []slack.Team{
						{ID: "2", Name: "OtherTeam2"},
					},
					Cursor: "",
					Err:    nil,
				},
			},
			expectedTeam:      nil,
			expectedErrSubstr: "team 'TeamNotFound' not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockSlackClient{
				listTeamsResponses: tt.mockResponses,
			}

			team, err := getTeam(client, tt.teamNameToSearch)
			if tt.expectedTeam != nil {
				assert.NoError(t, err)
				assert.NotNil(t, team)
				assert.Equal(t, *tt.expectedTeam, *team)
			} else {
				assert.Nil(t, team)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrSubstr)
			}
		})
	}
}

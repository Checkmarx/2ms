package slack

import (
	"fmt"

	"github.com/slack-go/slack"
)

type ISlackClient interface {
	GetConversations(*slack.GetConversationsParameters) ([]slack.Channel, string, error)
	ListTeams(slack.ListTeamsParameters) ([]slack.Team, string, error)
}

func getTeam(slackApi ISlackClient, teamName string) (*slack.Team, error) {
	cursorHolder := ""
	for {
		teams, cursor, err := slackApi.ListTeams(slack.ListTeamsParameters{Cursor: cursorHolder})
		if err != nil {
			return nil, fmt.Errorf("error while getting teams: %w", err)
		}
		for _, team := range teams {
			if team.Name == teamName || team.ID == teamName {
				return &team, nil
			}
		}
		if cursor == "" {
			break
		}
		cursorHolder = cursor
	}
	return nil, fmt.Errorf("team '%s' not found", teamName)
}

func getChannels(slackApi ISlackClient, teamId string, wantedChannels []string) (*[]slack.Channel, error) {
	cursorHolder := ""
	selectedChannels := []slack.Channel{}
	for {
		channels, cursor, err := slackApi.GetConversations(&slack.GetConversationsParameters{
			Cursor: cursorHolder,
			TeamID: teamId,
		})
		if err != nil {
			return nil, fmt.Errorf("error while getting channels: %w", err)
		}
		if len(wantedChannels) == 0 {
			selectedChannels = append(selectedChannels, channels...)
		} else {
			for _, channel := range wantedChannels {
				for _, c := range channels {
					if c.Name == channel || c.ID == channel {
						selectedChannels = append(selectedChannels, c)
					}
				}
			}
			if len(selectedChannels) == len(wantedChannels) {
				return &selectedChannels, nil
			}
		}
		if cursor == "" {
			return &selectedChannels, nil
		}
		cursorHolder = cursor
	}
}

package plugins

import (
	"fmt"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/slack-go/slack"
	"github.com/spf13/cobra"
)

const (
	slackTokenFlag            = "token"
	slackTeamFlag             = "team"
	slackChannelFlag          = "channel"
	slackBackwardDurationFlag = "duration"
	slackMessagesCountFlag    = "messages-count"
)

const slackDefaultDateFrom = time.Hour * 24 * 14

type SlackPlugin struct {
	Plugin
	Channels
	Token string
}

func (p *SlackPlugin) GetName() string {
	return "slack"
}

var (
	tokenArg            string
	teamArg             string
	channelsArg         []string
	backwardDurationArg time.Duration
	messagesCountArg    int
)

func (p *SlackPlugin) DefineCommand(channels Channels) (*cobra.Command, error) {
	p.Channels = channels

	command := &cobra.Command{
		Use:   fmt.Sprintf("%s --%s TOKEN --%s TEAM", p.GetName(), slackTokenFlag, slackTeamFlag),
		Short: "Scan Slack workspace",
		Long:  "Scan Slack workspace for sensitive information.",
		Run: func(cmd *cobra.Command, args []string) {
			p.getItems()
		},
	}

	command.Flags().StringVar(&tokenArg, slackTokenFlag, "", "Slack token [required]")
	err := command.MarkFlagRequired(slackTokenFlag)
	if err != nil {
		return nil, fmt.Errorf("error while marking flag %s as required: %w", slackTokenFlag, err)
	}
	command.Flags().StringVar(&teamArg, slackTeamFlag, "", "Slack team name or ID [required]")
	err = command.MarkFlagRequired(slackTeamFlag)
	if err != nil {
		return nil, fmt.Errorf("error while marking flag %s as required: %w", slackTeamFlag, err)
	}
	command.Flags().StringArrayVar(&channelsArg, slackChannelFlag, []string{}, "Slack channels to scan")
	command.Flags().DurationVar(&backwardDurationArg, slackBackwardDurationFlag, slackDefaultDateFrom, "Slack backward duration for messages (ex: 24h, 7d, 1M, 1y)")
	command.Flags().IntVar(&messagesCountArg, slackMessagesCountFlag, 0, "Slack messages count")

	return command, nil
}

func (p *SlackPlugin) getItems() {
	slackApi := slack.New(tokenArg)

	team, err := getTeam(slackApi, teamArg)
	if err != nil {
		p.Errors <- fmt.Errorf("error while getting team: %w", err)
		return
	}

	channels, err := getChannels(slackApi, team.ID, channelsArg)
	if err != nil {
		p.Errors <- fmt.Errorf("error while getting channels for team %s: %w", team.Name, err)
		return
	}
	if len(*channels) == 0 {
		log.Warn().Msgf("No channels found for team %s", team.Name)
		return
	}

	log.Info().Msgf("Found %d channels for team %s", len(*channels), team.Name)
	p.WaitGroup.Add(len(*channels))
	for _, channel := range *channels {
		go p.getItemsFromChannel(slackApi, channel)
	}
}

func (p *SlackPlugin) getItemsFromChannel(slackApi *slack.Client, channel slack.Channel) {
	defer p.WaitGroup.Done()
	log.Info().Msgf("Getting items from channel %s", channel.Name)

	cursor := ""
	counter := 0
	for {
		history, err := slackApi.GetConversationHistory(&slack.GetConversationHistoryParameters{
			Cursor:    cursor,
			ChannelID: channel.ID,
		})
		if err != nil {
			p.Errors <- fmt.Errorf("error while getting history for channel %s: %w", channel.Name, err)
			return
		}
		for _, message := range history.Messages {
			outOfRange, err := isMessageOutOfRange(message, backwardDurationArg, counter, messagesCountArg)
			if err != nil {
				p.Errors <- fmt.Errorf("error while checking message: %w", err)
				return
			}
			if outOfRange {
				break
			}
			if message.Text != "" {
				p.Items <- Item{
					Content: message.Text,
					Source:  channel.Name,
					ID:      message.Timestamp,
				}
			}
			counter++
		}
		if history.ResponseMetaData.NextCursor == "" {
			break
		}
		cursor = history.ResponseMetaData.NextCursor
	}
}

func getTeam(slackApi *slack.Client, teamName string) (*slack.Team, error) {
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

func getChannels(slackApi *slack.Client, teamId string, wantedChannels []string) (*[]slack.Channel, error) {
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

// Declare it to be consistent with all comparaisons
var timeNow = time.Now()

func isMessageOutOfRange(message slack.Message, backwardDuration time.Duration, currentMessagesCount int, limitMessagesCount int) (bool, error) {
	if backwardDuration != 0 {
		timestamp, err := strconv.ParseFloat(message.Timestamp, 64)
		if err != nil {
			return true, fmt.Errorf("error while parsing timestamp: %w", err)
		}
		messageDate := time.Unix(int64(timestamp), 0)
		if messageDate.Before(timeNow.Add(-backwardDuration)) {
			return true, nil
		}
	}
	if limitMessagesCount != 0 && currentMessagesCount >= limitMessagesCount {
		return true, nil
	}
	return false, nil
}

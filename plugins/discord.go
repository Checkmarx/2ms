package plugins

import (
	"fmt"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const (
	tokenFlag         = "token"
	serversFlag       = "server"
	channelsFlag      = "channel"
	fromDateFlag      = "duration"
	messagesCountFlag = "messages-count"
)

const defaultDateFrom = time.Hour * 24 * 14

type DiscordPlugin struct {
	Token            string
	Guilds           []string
	Channels         []string
	Count            int
	BackwardDuration time.Duration
	Session          *discordgo.Session

	errChan   chan error
	itemChan  chan Item
	waitGroup *sync.WaitGroup
}

func (p *DiscordPlugin) GetName() string {
	return "discord"
}

func (p *DiscordPlugin) DefineCommand(channels Channels) (*cobra.Command, error) {
	var discordCmd = &cobra.Command{
		Use:   fmt.Sprintf("%s --%s TOKEN --%s SERVER", p.GetName(), tokenFlag, serversFlag),
		Short: "Scan Discord server",
		Long:  "Scan Discord server for sensitive information.",
	}
	flags := discordCmd.Flags()

	flags.StringVar(&p.Token, tokenFlag, "", "Discord token [required]")
	err := discordCmd.MarkFlagRequired(tokenFlag)
	if err != nil {
		return nil, fmt.Errorf("error while marking '%s' flag as required: %w", tokenFlag, err)
	}
	flags.StringSliceVar(&p.Guilds, serversFlag, []string{}, "Discord servers IDs to scan [required]")
	err = discordCmd.MarkFlagRequired(serversFlag)
	if err != nil {
		return nil, fmt.Errorf("error while marking '%s' flag as required: %w", serversFlag, err)
	}
	flags.StringSliceVar(&p.Channels, channelsFlag, []string{}, "Discord channels IDs to scan. If not provided, all channels will be scanned")
	flags.DurationVar(&p.BackwardDuration, fromDateFlag, defaultDateFrom, "The time interval to scan from the current time. For example, 24h for 24 hours or 336h0m0s for 14 days.")
	flags.IntVar(&p.Count, messagesCountFlag, 0, "The number of messages to scan. If not provided, all messages will be scanned until the fromDate flag value.")

	discordCmd.Run = func(cmd *cobra.Command, args []string) {
		err := p.initialize(cmd)
		if err != nil {
			channels.Errors <- fmt.Errorf("discord plugin initialization failed: %w", err)
			return
		}

		p.getItems(channels.Items, channels.Errors, channels.WaitGroup)
	}

	return discordCmd, nil
}

func (p *DiscordPlugin) initialize(cmd *cobra.Command) error {
	if len(p.Channels) == 0 {
		log.Warn().Msg("discord channels not provided. Will scan all channels")
	}

	if p.Count == 0 && p.BackwardDuration == 0 {
		return fmt.Errorf("discord messages count or from date arg is missing. Plugin initialization failed")
	}

	return nil
}

func (p *DiscordPlugin) getItems(itemsChan chan Item, errChan chan error, wg *sync.WaitGroup) {
	p.errChan = errChan
	p.itemChan = itemsChan
	p.waitGroup = wg

	err := p.getDiscordReady()
	if err != nil {
		errChan <- err
		return
	}

	guilds := p.getGuildsByNameOrIDs()
	log.Info().Msgf("Found %d guilds", len(guilds))

	p.waitGroup.Add(len(guilds))
	for _, guild := range guilds {
		go p.readGuildMessages(guild)
	}
}

func (p *DiscordPlugin) getDiscordReady() (err error) {
	p.Session, err = discordgo.New(p.Token)
	if err != nil {
		return err
	}

	p.Session.StateEnabled = true
	ready := make(chan error)
	p.Session.AddHandlerOnce(func(s *discordgo.Session, r *discordgo.Ready) {
		ready <- nil
	})
	go func() {
		err := p.Session.Open()
		if err != nil {
			ready <- err
		}
	}()
	time.AfterFunc(time.Second*10, func() {
		ready <- fmt.Errorf("discord session timeout")
	})

	err = <-ready
	if err != nil {
		return err
	}

	return nil
}

func (p *DiscordPlugin) getGuildsByNameOrIDs() []*discordgo.Guild {
	var result []*discordgo.Guild

	for _, guild := range p.Guilds {
		for _, g := range p.Session.State.Guilds {
			if g.Name == guild || g.ID == guild {
				result = append(result, g)
			}
		}
	}

	return result
}

func (p *DiscordPlugin) readGuildMessages(guild *discordgo.Guild) {
	defer p.waitGroup.Done()

	guildLogger := log.With().Str("guild", guild.Name).Logger()
	guildLogger.Debug().Send()

	selectedChannels := p.getChannelsByNameOrIDs(guild)
	guildLogger.Info().Msgf("Found %d channels", len(selectedChannels))

	p.waitGroup.Add(len(selectedChannels))
	for _, channel := range selectedChannels {
		go p.readChannelMessages(channel)
	}
}

func (p *DiscordPlugin) getChannelsByNameOrIDs(guild *discordgo.Guild) []*discordgo.Channel {
	var result []*discordgo.Channel
	if len(p.Channels) == 0 {
		return guild.Channels
	}

	for _, channel := range p.Channels {
		for _, c := range guild.Channels {
			if c.Name == channel || c.ID == channel {
				result = append(result, c)
			}
		}
	}

	return result
}

func (p *DiscordPlugin) readChannelMessages(channel *discordgo.Channel) {
	defer p.waitGroup.Done()

	channelLogger := log.With().Str("guildID", channel.GuildID).Str("channel", channel.Name).Logger()
	channelLogger.Debug().Send()

	permission, err := p.Session.UserChannelPermissions(p.Session.State.User.ID, channel.ID)
	if err != nil {
		if err, ok := err.(*discordgo.RESTError); ok {
			if err.Message.Code == 50001 {
				channelLogger.Debug().Msg("No read permissions")
				return
			}
		}

		channelLogger.Error().Err(err).Msg("Failed to get permissions")
		p.errChan <- err
		return
	}
	if permission&discordgo.PermissionViewChannel == 0 {
		channelLogger.Debug().Msg("No read permissions")
		return
	}
	if channel.Type != discordgo.ChannelTypeGuildText {
		channelLogger.Debug().Msg("Not a text channel")
		return
	}

	messages, err := p.getMessages(channel.ID, channelLogger)
	if err != nil {
		channelLogger.Error().Err(err).Msg("Failed to get messages")
		p.errChan <- err
		return
	}
	channelLogger.Info().Msgf("Found %d messages", len(messages))

	items := convertMessagesToItems(p.GetName(), channel.GuildID, &messages)
	for _, item := range *items {
		p.itemChan <- item
	}
}

func (p *DiscordPlugin) getMessages(channelID string, logger zerolog.Logger) ([]*discordgo.Message, error) {
	var messages []*discordgo.Message
	threadMessages := []*discordgo.Message{}

	var beforeID string

	m, err := p.Session.ChannelMessages(channelID, 100, beforeID, "", "")
	if err != nil {
		return nil, err
	}

	lastMessage := false
	for len(m) > 0 && !lastMessage {

		for _, message := range m {

			timeSince := time.Since(message.Timestamp)
			if p.BackwardDuration > 0 && timeSince > p.BackwardDuration {
				logger.Debug().Msgf("Reached time limit (%s). Last message is %s old", p.BackwardDuration.String(), timeSince.Round(time.Hour).String())
				lastMessage = true
				break
			}

			if p.Count > 0 && len(messages) == p.Count {
				logger.Debug().Msgf("Reached message count (%d)", p.Count)
				lastMessage = true
				break
			}

			if message.Thread != nil {
				logger.Info().Msgf("Found thread %s", message.Thread.Name)
				tMgs, err := p.getMessages(message.Thread.ID, logger.With().Str("thread", message.Thread.Name).Logger())
				if err != nil {
					return nil, err
				}
				threadMessages = append(threadMessages, tMgs...)
			}

			messages = append(messages, message)
			beforeID = message.ID
		}

		m, err = p.Session.ChannelMessages(channelID, 100, beforeID, "", "")
		if err != nil {
			return nil, err
		}
	}

	return append(messages, threadMessages...), nil
}

func convertMessagesToItems(pluginName, guildId string, messages *[]*discordgo.Message) *[]Item {
	items := []Item{}
	for _, message := range *messages {
		items = append(items, Item{
			Content:     message.Content,
			ID:          fmt.Sprintf("%s-%s-%s-%s", pluginName, guildId, message.ChannelID, message.ID),
			Description: fmt.Sprintf("https://discord.com/channels/%s/%s/%s", guildId, message.ChannelID, message.ID),
		})
	}
	return &items
}
